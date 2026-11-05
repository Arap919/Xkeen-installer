// @vitest-environment jsdom
import {describe,it,expect,vi} from 'vitest';
import {Wizard, type Backend} from './wizard';
import {mount} from './ui';

function fixture() {
 let starts=0;
 const backend={
  Inspect:async()=>({ID:'inspection',Arch:'aarch64',Entware:true,Available:100000000,ActiveCore:'mihomo',Versions:{}}),
  PreparePlan:async()=>({ID:'plan',Steps:[],Changes:[],Artifacts:[],Dependencies:[],Notes:[],Files:[],Conflicts:[],Message:''}),
  ConfirmPlan:async()=>{}, StartInstall:async()=>{starts++},CancelInstall:async()=>{},
  GetResult:async()=>({Status:'installed',Message:'Операции выполнены',Services:[]}),
  EndSession:async()=>{},ExportRedactedReport:async()=>'{}',
  ConfirmHostKey:async()=>{},PrepareTrust:async()=>({ID:'ca',Description:'Добавить CA',Manual:''}),ApplyTrust:async()=>({Detail:'Ожидает проверки'}),Verify:async()=>({Status:'installed',Message:'Проверено',Services:[]})
 } satisfies Backend;
 return {wizard:new Wizard(backend),starts:()=>starts};
}

describe('wizard safety transitions',()=>{
 it('renders each backend file preview as text before plan confirmation',async()=>{
  const {wizard}=fixture();await wizard.inspect();await wizard.prepare();
  const path='/opt/etc/mihomo/<preview>.yaml';
  const preview='secret: <redacted>\n# <img src=x onerror="alert(1)">';
  wizard.plan!.Files=[{Path:path,Action:'preserve',Preview:preview}];
  const root=document.createElement('div');mount(root,wizard);
  const rendered=root.querySelector('.file-previews pre')!;
  expect(rendered?.textContent).toBe(preview);
  expect(root.querySelector('.file-previews summary')?.textContent).toContain(path);
  expect(root.querySelector('.file-previews img')).toBeNull();
  expect(rendered.compareDocumentPosition(root.querySelector('#reviewed')!)&Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
 });
 it('returns to plan review when the backend rejects installation start',async()=>{
  const {wizard}=fixture();await wizard.inspect();await wizard.prepare();wizard.reviewed=true;
  wizard.backend.StartInstall=async()=>{throw new Error('rejected');};
  await wizard.start();
  expect(wizard.step).toBe(6);expect(wizard.running).toBe(false);expect(wizard.plan).toBeNull();
  const root=document.createElement('div');mount(root,wizard);
  expect(root.querySelector('h1')?.textContent).toBe('План изменений');
  expect(root.textContent).not.toContain('Выполняется подтверждённый план');
  expect(root.querySelector('[data-action="start"]')).toBeNull();
 });
 it('uses Russian progress labels while keeping backend event IDs internal',()=>{
  const {wizard}=fixture();wizard.step=7;wizard.running=true;wizard.progress=[{Step:'download',Status:'running',Message:''}];
  const root=document.createElement('div');mount(root,wizard);
  expect(root.querySelector('.progress')?.textContent).toContain('Загрузка');
  expect(root.querySelector('.progress')?.textContent).not.toContain('download');
 });
 it('shows completed changes and cannot navigate back into a finished runner',()=>{
  const {wizard}=fixture();wizard.step=8;wizard.result={Status:'cancelled',Message:'Остановлено',Completed:['backup'],Applied:['/opt/sbin/mihomo'],Services:[]};
  const root=document.createElement('div');mount(root,wizard);
  expect(root.textContent).toContain('/opt/sbin/mihomo');
  expect(root.querySelector<HTMLButtonElement>('[data-action="back"]')?.disabled).toBe(true);
 });
 it('keeps the result when a runner finishes before the start response',async()=>{
  const {wizard}=fixture();await wizard.inspect();await wizard.prepare();wizard.reviewed=true;
  wizard.backend.StartInstall=async()=>{await wizard.finish();};
  await wizard.start();expect(wizard.step).toBe(8);expect(wizard.running).toBe(false);
 });
 it('navigates the actual screens with a fake backend and requires review before writing',async()=>{
  const {wizard,starts}=fixture();const root=document.createElement('div');mount(root,wizard);
  const click=(action:string)=>root.querySelector<HTMLButtonElement>(`[data-action="${action}"]`)!.click();
  const prepared=root.querySelector<HTMLInputElement>('#prepared')!;prepared.checked=true;prepared.dispatchEvent(new Event('change',{bubbles:true}));click('next');
  expect(root.querySelector('h1')?.textContent).toBe('Подключение');
  click('inspect');await vi.waitFor(()=>expect(root.querySelector('h1')?.textContent).toBe('Проверка роутера'));
  click('next');click('next');click('next');
  expect(root.querySelector('h1')?.textContent).toBe('Конфигурация');
  click('prepare');await vi.waitFor(()=>expect(root.querySelector('h1')?.textContent).toBe('План изменений'));
  expect(root.querySelector<HTMLButtonElement>('[data-action="start"]')?.disabled).toBe(true);
  const reviewed=root.querySelector<HTMLInputElement>('#reviewed')!;reviewed.checked=true;reviewed.dispatchEvent(new Event('change',{bubbles:true}));click('start');
  await vi.waitFor(()=>expect(starts()).toBe(1));expect(wizard.step).toBe(7);
  await wizard.finish();expect(wizard.step).toBe(8);expect(wizard.result?.Status).toBe('installed');
 });
 it('renders nine stages and disables unacknowledged preparation',()=>{
  const {wizard}=fixture();const root=document.createElement('div');mount(root,wizard);
  expect(root.querySelectorAll('nav li')).toHaveLength(9);
  expect(root.querySelector<HTMLButtonElement>('[data-action="next"]')?.disabled).toBe(true);
  const prepared=root.querySelector<HTMLInputElement>('#prepared')!;prepared.checked=true;prepared.dispatchEvent(new Event('change',{bubbles:true}));
  expect(root.querySelector<HTMLButtonElement>('[data-action="next"]')?.disabled).toBe(false);
 });
 it('cannot skip inspection or the reviewed plan',()=>{
  const {wizard}=fixture(); wizard.step=1;
  expect(wizard.next()).toBe(false); expect(wizard.step).toBe(1);
  wizard.step=6; expect(wizard.next()).toBe(false);
 });
 it('invalidates inspection and plan when connection changes',async()=>{
  const {wizard}=fixture(); await wizard.inspect(); await wizard.prepare();
  wizard.connectionChanged(); expect(wizard.inspection).toBeNull(); expect(wizard.plan).toBeNull();
 });
 it('requires explicit review and prevents double start',async()=>{
  const {wizard,starts}=fixture(); await wizard.inspect(); await wizard.prepare();
  await wizard.start(); expect(starts()).toBe(0);
  wizard.reviewed=true; await Promise.all([wizard.start(),wizard.start()]);
  expect(starts()).toBe(1);
 });
 it('clears credentials after inspection and sensitive imports on completion',async()=>{
  const {wizard}=fixture(); wizard.connection.Password='private'; await wizard.inspect();
  expect(wizard.connection.Password).toBe('');
  wizard.selection.ProviderURL='https://private.example/key'; wizard.selection.ImportText='secret';
  await wizard.finish(); expect(wizard.selection.ProviderURL).toBe(''); expect(wizard.selection.ImportText).toBe('');
 });
 it('cancel requires new inspection and never claims rollback',async()=>{
  const {wizard}=fixture(); await wizard.inspect(); await wizard.prepare(); wizard.reviewed=true; await wizard.start();
  await wizard.cancel(); expect(wizard.inspection).toBeNull(); expect(wizard.plan).toBeNull();
  expect(wizard.message).toContain('не откатывает');
 });
});
