// @vitest-environment jsdom
import {it,expect,vi} from 'vitest';
import {Wizard,type Backend} from './wizard';
import {mount} from './ui';
it('separates firmware discovery from reviewed bootstrap and shell readiness',async()=>{
 const start=vi.fn(async()=>{});const inspect=vi.fn();
 const backend={Inspect:inspect,DiscoverBootstrap:async()=>({Model:'Ultra',Hardware:'KN-2410',Arch:'mips',Volumes:[{UUID:'1234',Label:'ENTWARE',Free:100000000,Share:'ENTWARE'}]}),PrepareBootstrap:async()=>({ID:'review',Model:'Ultra',Hardware:'KN-2410',Arch:'mips',Volume:{UUID:'1234',Label:'ENTWARE',Free:100000000,Share:'ENTWARE'},Archive:'mips-installer.tar.gz',URL:'https://bin.entware.net/archive',SHA256:'abc',Size:3000000,Commands:['opkg disk 1234:/'],IntegritySource:'installer review'}),StartBootstrap:start} as unknown as Backend;
 const w=new Wizard(backend);w.setMode('new');expect(w.connection.Port).toBe(22);expect(w.connection.User).toBe('admin');w.connection.Password='transient';await w.inspect();expect(inspect).not.toHaveBeenCalled();expect(w.inspection).toBeNull();expect(w.step).toBe(2);
 await w.prepareBootstrap();await w.startBootstrap();expect(start).not.toHaveBeenCalled();w.bootstrapReviewed=true;await w.startBootstrap();expect(start).toHaveBeenCalledWith('review',true);expect(w.inspection).toBeNull();expect(w.connection.Password).toBe('');
 const root=document.createElement('div');w.running=false;w.bootstrapWaiting=true;mount(root,w);expect(root.textContent).toContain('SSH Entware');expect(root.textContent).not.toContain('Entware установлен');
});

it('reports the failing new-install stage without exposing backend details',async()=>{
 for(const [code,expected] of [
  ['SSH_AUTH','администратора'],['SSH_CONNECT','22'],['BOOTSTRAP_VERSION','show version'],
  ['BOOTSTRAP_MEDIA','show media'],['BOOTSTRAP_CONFIG','show running-config'],['BOOTSTRAP_CIFS','show cifs'],['BOOTSTRAP_CIFS_PARSE','разбор'],
  ['BOOTSTRAP_PARSE','разобрать'],['BOOTSTRAP_SMB','SMB'],['BOOTSTRAP_TARGET','EXT4'],
 ]){
  const backend={DiscoverBootstrap:async()=>{throw new Error(`[${code}] private-password configuration-secret`);}} as unknown as Backend;
  const w=new Wizard(backend);w.setMode('new');w.connection.Password='transient';await w.inspect();
  expect(w.message).toContain(expected);expect(w.message).toContain(`[${code}]`);
  expect(w.message).not.toContain('private-password');expect(w.message).not.toContain('configuration-secret');
  expect(w.connection.Password).toBe('');expect(w.bootstrap).toBeNull();expect(w.busy).toBe(false);
 }
 const w=new Wizard({DiscoverBootstrap:async()=>{throw 'unknown private-password';}} as unknown as Backend);
 w.setMode('new');await w.inspect();expect(w.message).not.toContain('private-password');
});

it('shows only the whitelisted CIFS schema diagnostic',async()=>{
 const backend={DiscoverBootstrap:async()=>{throw '[BOOTSTRAP_CIFS_PARSE] private-password CIFS/TEXT/7/none';}} as unknown as Backend;
 const w=new Wizard(backend);w.setMode('new');await w.inspect();
 expect(w.message).toContain('CIFS/TEXT/7/none');expect(w.message).not.toContain('private-password');
 backend.DiscoverBootstrap=async()=>{throw '[BOOTSTRAP_CIFS_PARSE] CIFS/private-password/7/private-value';};await w.inspect();
 expect(w.message).not.toContain('private-password');expect(w.message).not.toContain('private-value');
});


it('tracks the running-only bootstrap sequence without claiming shell readiness',async()=>{
 const backend={StartBootstrap:async()=>{},GetResult:async()=>({Status:'waiting-shell',Message:'Проверьте SSH Entware',Services:[]})} as unknown as Backend;
 const w=new Wizard(backend);w.mode='new';w.step=2;w.bootstrap={Model:'Ultra',Hardware:'KN-2410',Arch:'mips',Volumes:[]};w.bootstrapPlan={ID:'review'} as NonNullable<Wizard['bootstrapPlan']>;w.bootstrapReviewed=true;w.progress=[{Step:'install',Status:'completed',Message:''}];await w.startBootstrap();expect(w.progress).toEqual([]);
 for(const Step of ['reinspect','download','transfer','trigger','waiting-shell'])await w.receiveProgress({Step,Status:'running',Message:'secret'});
 expect(w.progress.map(stage=>stage.Status)).toEqual(['completed','completed','completed','completed','running']);
 await w.receiveProgress({Step:'transfer',Status:'running',Message:'late'});await w.receiveProgress({Step:'waiting-shell',Status:'running',Message:'duplicate'});
 expect(w.progress).toHaveLength(5);expect(w.progress[2].Status).toBe('completed');
 const root=document.createElement('div');mount(root,w);expect(root.querySelectorAll('.progress li')).toHaveLength(5);expect(root.textContent).toContain('Завершено этапов: 4');expect(root.textContent).toContain('Ожидание SSH Entware');expect(root.textContent).not.toMatch(/secret|late|duplicate|Entware установлен/);expect(root.querySelector('progress')).toBeNull();
 await w.receiveProgress({Step:'bootstrap-finished',Status:'waiting-shell',Message:'Проверьте SSH Entware'});expect(w.bootstrapWaiting).toBe(true);expect(w.progress).toHaveLength(5);expect(w.progress[4].Status).toBe('running');
});
it('ignores an out-of-order earlier bootstrap marker',async()=>{
 const w=new Wizard({} as Backend);w.mode='new';await w.receiveProgress({Step:'transfer',Status:'running',Message:''});await w.receiveProgress({Step:'download',Status:'running',Message:''});expect(w.progress).toEqual([{Step:'transfer',Status:'running',Message:''}]);
});
it.each(['transfer','waiting-shell'])('does not complete current bootstrap %s on failure',async Step=>{
 const w=new Wizard({GetResult:async()=>({Status:'bootstrap-partial',Message:'Нужна проверка SSH Entware',Services:[]})} as unknown as Backend);w.mode='new';await w.receiveProgress({Step,Status:'running',Message:''});await w.receiveProgress({Step:'bootstrap-finished',Status:'bootstrap-partial',Message:''});expect(w.progress).toEqual([{Step,Status:'running',Message:''}]);expect(w.result?.Status).toBe('bootstrap-partial');expect(w.bootstrapWaiting).toBe(true);
});
