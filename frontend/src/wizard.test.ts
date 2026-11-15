// @vitest-environment jsdom
import {describe,it,expect,vi} from 'vitest';
import {Wizard, type Backend, type Result} from './wizard';
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
 it('updates unique stages, ignores late running and renders real planned completion',async()=>{
  const {wizard:w}=fixture();await w.inspect();await w.prepare();w.plan!.Steps=[{ID:'download',Description:'Проверяем архив по SHA256'},{ID:'install',Description:'Устанавливаем выбранные компоненты'},{ID:'install',Description:'Повтор'}];w.reviewed=true;w.progress=[{Step:'backup',Status:'completed',Message:''}];await w.start();expect(w.progress).toEqual([]);
  w.receiveProgress({Step:'download',Status:'running',Message:'private stageRunning'});w.receiveProgress({Step:'download',Status:'completed',Message:'private stageCompleted'});w.receiveProgress({Step:'download',Status:'running',Message:'late'});w.receiveProgress({Step:'install',Status:'running',Message:'secret'});
  expect(w.progress).toHaveLength(2);expect(w.progress[0].Status).toBe('completed');const root=document.createElement('div');mount(root,w);expect(root.querySelectorAll('.progress li')).toHaveLength(2);expect(root.querySelector('progress')?.getAttribute('value')).toBe('1');expect(root.querySelector('progress')?.getAttribute('max')).toBe('2');expect(root.textContent).toContain('Выполнено этапов 1 из 2');expect(root.textContent).toContain('Проверяем архив по SHA256');expect(root.textContent).toContain('Устанавливаем выбранные компоненты');expect(root.querySelector('.progress li')?.textContent).toMatch(/артефактов\s+Завершено/);expect(root.textContent).not.toMatch(/private|stageRunning|stageCompleted|secret/);
 });
 it('routes terminal progress once without rendering terminal IDs',async()=>{
  const {wizard:w}=fixture();const finish=vi.spyOn(w,'finish').mockResolvedValue();const bootstrap=vi.spyOn(w,'finishBootstrap').mockResolvedValue();await Promise.all([w.receiveProgress({Step:'finished',Status:'completed',Message:''}),w.receiveProgress({Step:'finished',Status:'completed',Message:''}),w.receiveProgress({Step:'bootstrap-finished',Status:'completed',Message:''}),w.receiveProgress({Step:'bootstrap-finished',Status:'completed',Message:''})]);expect(finish).toHaveBeenCalledTimes(1);expect(bootstrap).toHaveBeenCalledTimes(1);expect(w.progress).toEqual([]);
 });
 it('uses unique received stages without inventing an overall total',()=>{
  const {wizard:w}=fixture();w.step=7;w.running=true;w.receiveProgress({Step:'download',Status:'running',Message:''});w.receiveProgress({Step:'download',Status:'completed',Message:''});const root=document.createElement('div');mount(root,w);expect(root.querySelectorAll('.progress li')).toHaveLength(1);expect(root.querySelector('progress')).toBeNull();expect(root.textContent).toContain('Завершено этапов: 1');
 });

 it('maps only nonblank subscriptions for selected cores and preserves legacy callers',async()=>{
  const {wizard}=fixture();await wizard.inspect();wizard.selection.Cores=['mihomo','xray'];
  wizard.selection.MihomoProviderURLs=[' https://a.example/key ',''];wizard.selection.XrayProviderURLs=['https://b.example/key','  '];
  const prepare=vi.spyOn(wizard.backend,'PreparePlan');await wizard.prepare();
  expect(prepare.mock.calls[0][0]).toMatchObject({MihomoProviderURLs:['https://a.example/key'],XrayProviderURLs:['https://b.example/key'],ProviderURL:''});
  wizard.selection.Cores=['mihomo'];await wizard.prepare();expect(prepare.mock.calls[1][0].XrayProviderURLs).toEqual([]);
  wizard.selection.MihomoProviderURLs=[];wizard.selection.ProviderURL='https://legacy.example/key';await wizard.prepare();expect(prepare.mock.calls[2][0].ProviderURL).toBe('https://legacy.example/key');
 });
 it('edits independent masked lists, caps each at ten and removes the selected row',()=>{
  const {wizard}=fixture();wizard.step=5;wizard.selection.Cores=['mihomo','xray'];const root=document.createElement('div');mount(root,wizard);
  const add=(core:string)=>root.querySelector<HTMLButtonElement>(`[data-action="add-provider"][data-core="${core}"]`)!;
  expect(root.querySelector<HTMLInputElement>('[data-provider="mihomo"]')!.type).toBe('password');
  const input=root.querySelector<HTMLInputElement>('[data-provider="mihomo"]')!;input.value='https://secret.example/key';input.dispatchEvent(new Event('input',{bubbles:true}));
  for(let i=0;i<12;i++)add('mihomo').click();
  expect(root.querySelectorAll('[data-provider="mihomo"]')).toHaveLength(10);expect(add('mihomo').disabled).toBe(true);
  expect(root.querySelectorAll('[data-provider="xray"]')).toHaveLength(1);expect(wizard.selection.XrayProviderURLs).toEqual([]);
  root.querySelector<HTMLButtonElement>('[data-action="remove-provider"][data-core="mihomo"][data-index="0"]')!.click();
  expect(root.querySelectorAll('[data-provider="mihomo"]')).toHaveLength(9);expect(wizard.selection.MihomoProviderURLs).not.toContain('https://secret.example/key');expect(add('mihomo').disabled).toBe(false);
 });
 it('invalidates the plan and clears stale legacy/import values on URL edits and core deselection',async()=>{
  const {wizard}=fixture();await wizard.inspect();await wizard.prepare();wizard.step=5;wizard.reviewed=true;wizard.selection.Cores=['mihomo','xray'];wizard.selection.XrayProviderURLs=['https://x.example/key'];wizard.selection.ProviderURL='legacy';wizard.selection.ImportText='private';
  const root=document.createElement('div');mount(root,wizard);const input=root.querySelector<HTMLInputElement>('[data-provider="mihomo"]')!;input.value='https://m.example/key';input.dispatchEvent(new Event('input',{bubbles:true}));
  expect(wizard.plan).toBeNull();expect(wizard.reviewed).toBe(false);expect(wizard.selection.ProviderURL).toBe('');expect(wizard.selection.ImportText).toBe('');
  wizard.step=3;mount(document.createElement('div'),wizard);const r=document.createElement('div');mount(r,wizard);const cores=r.querySelector<HTMLInputElement>('[name="cores"][value="mihomo"]')!;cores.checked=true;cores.dispatchEvent(new Event('change',{bubbles:true}));
  expect(wizard.selection.XrayProviderURLs).toEqual([]);expect(wizard.selection.MihomoProviderURLs).toEqual(['https://m.example/key']);
 });
 it('prepares on the first click after a subscription blur without exposing its value',async()=>{
  const {wizard}=fixture();await wizard.inspect();wizard.step=5;const prepare=vi.spyOn(wizard.backend,'PreparePlan');const root=document.createElement('div');mount(root,wizard);
  const input=root.querySelector<HTMLInputElement>('[data-provider="mihomo"]')!;input.value='https://private.example/token';input.dispatchEvent(new Event('input',{bubbles:true}));const button=root.querySelector<HTMLButtonElement>('[data-action="prepare"]')!;
  input.dispatchEvent(new Event('change',{bubbles:true}));button.click();await vi.waitFor(()=>expect(prepare).toHaveBeenCalledTimes(1));expect(root.textContent).not.toContain('https://private.example/token');
 });
 it('clears subscription lists when importing a local configuration',async()=>{
  const {wizard}=fixture();wizard.step=5;wizard.selection.MihomoProviderURLs=['https://m.example/key'];wizard.selection.XrayProviderURLs=['https://x.example/key'];wizard.selection.ProviderURL='legacy';const root=document.createElement('div');mount(root,wizard);
  const input=root.querySelector<HTMLInputElement>('#import-file')!;Object.defineProperty(input,'files',{value:[{size:2,text:async()=>'{}'}]});input.dispatchEvent(new Event('change',{bubbles:true}));
  await vi.waitFor(()=>expect(wizard.selection.ImportText).toBe('{}'));expect(wizard.selection.MihomoProviderURLs).toEqual([]);expect(wizard.selection.XrayProviderURLs).toEqual([]);expect(wizard.selection.ProviderURL).toBe('');
 });
 it.each(['start','finish','end'] as const)('clears all sensitive imports on %s',async action=>{
  const {wizard}=fixture();await wizard.inspect();await wizard.prepare();wizard.reviewed=true;wizard.selection.MihomoProviderURLs=['https://m.example/key'];wizard.selection.XrayProviderURLs=['https://x.example/key'];wizard.selection.ProviderURL='legacy';wizard.selection.ImportText='private';
  await wizard[action]();expect(wizard.selection.MihomoProviderURLs).toEqual([]);expect(wizard.selection.XrayProviderURLs).toEqual([]);expect(wizard.selection.ProviderURL).toBe('');expect(wizard.selection.ImportText).toBe('');
 });
 it('shows one exact sanitized subscription failure',async()=>{
  const {wizard}=fixture();await wizard.inspect();wizard.backend.PreparePlan=async()=>{throw '[SUBSCRIPTION/MIHOMO/URL/HTTP/1/0]';};await wizard.prepare();
  expect(wizard.message).toContain('Mihomo');expect(wizard.message).toContain('№1');expect(wizard.message).toContain('HTTPS');expect(wizard.message).not.toContain('Xray');expect(wizard.message).not.toContain('outbounds');
  wizard.backend.PreparePlan=async()=>{throw '[SUBSCRIPTION/XRAY/FETCH/HTTP_STATUS/2/403]';};await wizard.prepare();expect(wizard.message).toContain('403');expect(wizard.message).toContain('№2');
 });
 it.each(['Подписки: https://private.example/key','arbitrary-secret','[SUBSCRIPTION/MIHOMO/URL/HTTP/1/0] private-secret','[SUBSCRIPTION/MIHOMO/FETCH/DNS/1/0]','[SUBSCRIPTION/XRAY/FETCH/HTTP_STATUS/2/999]'])('rejects unrecognized plan diagnostics',async error=>{const {wizard}=fixture();await wizard.inspect();wizard.backend.PreparePlan=async()=>{throw error;};await wizard.prepare();expect(wizard.message).toBe('[PLAN/UNEXPECTED] Не удалось подготовить план: нераспознанная ошибка установщика.');});
 it.each([['[PLAN/INPUT/MIXED_SOURCES]','Одновременно'],['[PLAN/CONFIGURATION/MIHOMO_YAML]','YAML'],['[SUBSCRIPTION/MIHOMO/SELECTION/CORE_MISSING/1/0]','не выбрано']])('renders precise plan stage %s',async(error,detail)=>{const {wizard}=fixture();await wizard.inspect();wizard.backend.PreparePlan=async()=>{throw error;};await wizard.prepare();expect(wizard.message).toContain(detail);expect(wizard.message).toContain(error);});
 it('clears sensitive inputs when the desktop window unloads',async()=>{
  const {wizard}=fixture();const clear=vi.spyOn(Wizard.prototype,'clearSensitiveInputs');const root=document.createElement('div');root.id='app';document.body.append(root);
  Object.assign(window,{go:{main:{App:wizard.backend}}});await import('./main');window.dispatchEvent(new Event('beforeunload'));
  expect(clear).toHaveBeenCalledTimes(1);clear.mockRestore();root.remove();delete window.go;
 });
 it('translates cron and subscription progress stages',()=>{
  const {wizard}=fixture();wizard.step=7;wizard.running=true;wizard.progress=[{Step:'cron',Status:'running',Message:''},{Step:'subscriptions',Status:'running',Message:''}];const root=document.createElement('div');mount(root,wizard);
  expect(root.querySelector('.progress')!.textContent).toContain('планировщика');expect(root.querySelector('.progress')!.textContent).toContain('подписок');
 });
 it('starts inspection on the first click after password blur',async()=>{
  const {wizard}=fixture();wizard.step=1;const inspect=vi.spyOn(wizard.backend,'Inspect');
  const root=document.createElement('div');document.body.append(root);mount(root,wizard);
  const password=root.querySelector<HTMLInputElement>('#password')!;
  password.focus();password.value='private';password.dispatchEvent(new Event('input',{bubbles:true}));
  const button=root.querySelector<HTMLButtonElement>('[data-action="inspect"]')!;
  password.dispatchEvent(new Event('change',{bubbles:true}));button.click();
  await vi.waitFor(()=>expect(inspect).toHaveBeenCalledTimes(1));root.remove();
 });
 it('toggles password visibility without losing value, focus or selection',()=>{
  const {wizard}=fixture();wizard.step=1;const root=document.createElement('div');document.body.append(root);mount(root,wizard);
  const password=root.querySelector<HTMLInputElement>('#password')!;password.value='private';password.dispatchEvent(new Event('input',{bubbles:true}));password.focus();password.setSelectionRange(2,5);
  expect(password.type).toBe('password');
  root.querySelector<HTMLButtonElement>('[data-action="toggle-password"]')!.click();
  expect(password.type).toBe('text');expect(password.value).toBe('private');expect(document.activeElement).toBe(password);expect(password.selectionStart).toBe(2);expect(password.selectionEnd).toBe(5);
  root.querySelector<HTMLButtonElement>('[data-action="toggle-password"]')!.click();expect(password.type).toBe('password');root.remove();
 });
 it('explains a safe SSH stage without exposing arbitrary backend errors',async()=>{
  const {wizard}=fixture();wizard.backend.Inspect=async()=>{throw '[SSH_SHELL] raw-private-value';};await wizard.inspect();
  expect(wizard.message).toContain('CLI KeeneticOS');expect(wizard.message).toContain('222');expect(wizard.message).not.toContain('raw-private-value');
  wizard.backend.Inspect=async()=>{throw new Error('password=private');};await wizard.inspect();expect(wizard.message).not.toContain('password=private');
 });
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

function uiResult(trust='pending',https='passed',api='passed'):Result{
 const passed={State:'passed',Detail:''};
 return {Status:'installed',Message:'Installed',Completed:['install'],Services:[{Component:'ui',Process:passed,Configuration:passed,API:{State:api,Detail:''},HTTPS:{State:https,Detail:''},Trust:{State:trust,Detail:''}}],PanelURL:trust==='passed'&&https==='passed'&&api==='passed'?'https://192.0.2.1:2050':''};
}
function completionFixture(report=uiResult()){
 const {wizard:w}=fixture();w.step=8;w.result={Status:'installed',Message:'Installed',Completed:['install'],Services:[]};
 const verify=vi.spyOn(w.backend,'Verify').mockResolvedValue(report);
 const prepare=vi.spyOn(w.backend,'PrepareTrust');const apply=vi.spyOn(w.backend,'ApplyTrust');return {w,verify,prepare,apply};
}
describe('automatic CA completion',()=>{
 it('verifies before opening exact CA consent and never imports automatically',async()=>{
  const {w,verify,prepare,apply}=completionFixture();await w.completeUISetup();
  expect(verify).toHaveBeenCalledTimes(1);expect(prepare).toHaveBeenCalledTimes(1);expect(verify.mock.invocationCallOrder[0]).toBeLessThan(prepare.mock.invocationCallOrder[0]);expect(w.trust?.ID).toBe('ca');expect(apply).not.toHaveBeenCalled();expect(w.result?.Completed).toEqual(['install']);
 });
 it('skips consent when already trusted',async()=>{const {w,prepare}=completionFixture(uiResult('passed'));await w.completeUISetup();expect(prepare).not.toHaveBeenCalled();expect(w.result?.PanelURL).toContain('2050');});
 it('preserves installation after refusal and ignores duplicate completion',async()=>{const {w,prepare,apply}=completionFixture();await w.completeUISetup();w.rejectTrust();await w.completeUISetup();expect(w.trust).toBeNull();expect(w.result?.Status).toBe('installed');expect(prepare).toHaveBeenCalledTimes(1);expect(apply).not.toHaveBeenCalled();});
 it.each(['cancelled','command_failed','verification_pending'])('reverifies %s without claiming readiness',async code=>{const {w,verify}=completionFixture();w.backend.ApplyTrust=vi.fn(async()=>({Status:'pending',Code:code,Detail:'CA import result'}));await w.completeUISetup();await w.applyTrust();expect(verify).toHaveBeenCalledTimes(2);expect(w.result?.PanelURL).toBe('');expect(w.result?.Status).toBe('installed');expect(w.trust).toBeNull();});
 it('exposes panel only after system verification passes',async()=>{const {w,verify}=completionFixture();await w.completeUISetup();verify.mockResolvedValueOnce(uiResult('passed'));await w.applyTrust();expect(w.result?.PanelURL).toContain('2050');});
 it.each([['failed','passed','HTTPS'],['passed','failed','API']])('blocks consent for failed %s/%s',async(https,api,detail)=>{const {w,prepare,apply}=completionFixture(uiResult('pending',https,api));await w.completeUISetup();await w.prepareTrust();await w.applyTrust();expect(prepare).not.toHaveBeenCalled();expect(apply).not.toHaveBeenCalled();expect(w.result?.Message).toContain(detail);expect(w.result?.PanelURL).toBe('');});
 it.each(['IMPORT','VERIFY'])('keeps %s failures distinct',async stage=>{const {w,verify}=completionFixture();await w.completeUISetup();if(stage==='IMPORT')w.backend.ApplyTrust=vi.fn(async()=>{throw Error('private-error');});else verify.mockRejectedValueOnce(Error('private-error'));await w.applyTrust();expect(w.message).toContain(`[CA/${stage}]`);expect(w.message).not.toContain('private-error');expect(w.result?.Completed).toEqual(['install']);expect(w.completionBusy).toBe(false);});
 it('identifies preparation failures',async()=>{const {w,prepare}=completionFixture();prepare.mockRejectedValueOnce(Error('private-error'));await w.completeUISetup();expect(w.message).toContain('[CA/PREPARE]');expect(w.message).not.toContain('private-error');});
 it('holds a separate completion lock while start response finishes',async()=>{const {wizard:w}=fixture();await w.inspect();await w.prepare();w.reviewed=true;let release!:(r:Result)=>void;let completion!:Promise<void>;vi.spyOn(w.backend,'Verify').mockImplementation(()=>new Promise(resolve=>{release=resolve;}));w.backend.StartInstall=async()=>{await w.finish();completion=w.completeUISetup();};await w.start();expect(w.busy).toBe(false);expect(w.completionBusy).toBe(true);release(uiResult());await completion;expect(w.completionBusy).toBe(false);expect(w.trust?.ID).toBe('ca');});
});

it('main verifies automatically after finished and suppresses duplicate events',async()=>{
 vi.resetModules();const {wizard:w}=fixture();const prepare=vi.spyOn(w.backend,'PrepareTrust');
 let release!:(r:Result)=>void;const verify=vi.spyOn(w.backend,'Verify').mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
 let progress!:(event:{Step:string;Status:string;Message:string})=>Promise<void>;
 const root=document.createElement('div');root.id='app';document.body.append(root);
 Object.assign(window,{go:{main:{App:w.backend}},runtime:{EventsOnMultiple:(_name:string,callback:typeof progress)=>{progress=callback;return ()=>{};}}});
 try{await import('./main');const event={Step:'finished',Status:'completed',Message:''};const first=progress(event);
 await vi.waitFor(()=>expect(verify).toHaveBeenCalledTimes(1));expect(root.querySelector('h1')?.textContent).toBe('Результат');expect(root.querySelector<HTMLButtonElement>('[data-action="verify"]')?.disabled).toBe(true);
 const duplicate=progress(event);release(uiResult());await Promise.all([first,duplicate]);expect(verify).toHaveBeenCalledTimes(1);expect(prepare).toHaveBeenCalledTimes(1);expect(root.querySelector('[data-action="apply-trust"]')).not.toBeNull();
 }finally{root.remove();delete window.go;delete window.runtime;}
});
