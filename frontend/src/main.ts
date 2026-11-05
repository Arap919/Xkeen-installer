import './style.css';
import {Wizard,type Backend} from './wizard';
import {mount} from './ui';
declare global{interface Window{go?:{main?:{App?:Backend}};runtime?:{EventsOnMultiple:(name:string,callback:(data:{Step:string;Status:string;Message:string})=>void,count:number)=>()=>void}}}
const root=document.querySelector<HTMLElement>('#app')!;
const backend=window.go?.main?.App;
if(!backend){root.textContent='Интерфейс нужно открыть в desktop-приложении XKeen Installer.';}
else{
 const wizard=new Wizard(backend);const render=mount(root,wizard);
 const off=window.runtime?.EventsOnMultiple('install:progress',async event=>{wizard.progress.push(event);if(event.Step==='finished'){await wizard.finish();}render();},-1);
 window.addEventListener('beforeunload',()=>{wizard.connection.Password='';wizard.selection.ImportText='';wizard.selection.ProviderURL='';off?.();});
}
