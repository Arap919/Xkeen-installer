export type HostKey={Kind:string;Address:string;Fingerprint:string;Expected:string;Algorithm:string};
export type Inspection={ID:string;Arch:string;Entware:boolean;Available:number;ActiveCore:string;Versions:Record<string,string>;HostKey?:HostKey|null};
export type Plan={ID:string;Steps:{ID:string;Description:string}[]|null;Changes:{Path:string;Action:string;Mode:string}[]|null;Artifacts:{Component:string;Version:string}[]|null;Dependencies:string[]|null;Notes:string[]|null;Files:{Path:string;Action:string;Preview:string}[]|null;Conflicts:{Path:string;Reason:string;NecessaryAddition:string}[]|null;Message:string};
export type Check={State:string;Detail:string};
export type Result={Status:string;Message:string;Backup?:string;Completed?:string[];Applied?:string[];Uncertain?:string;Pending?:string[];PanelURL?:string;Services:{Component:string;Process:Check;Configuration:Check;API:Check;HTTPS:Check;Trust:Check}[]|null};
export type Connection={Host:string;Port:number;User:string;Password:string};
export type Selection={Cores:string[];ActiveCore:string;UI:boolean;Watchdog:boolean;ImportCore:string;ImportText:string;ProviderURL:string};
export type Trust={ID:string;Description:string;Manual:string};
export interface Backend{
 Inspect(c:Connection):Promise<Inspection>;
 ConfirmHostKey(address:string,fingerprint:string):Promise<void>;
 PreparePlan(r:Selection&{InspectionID:string}):Promise<Plan>;
 ConfirmPlan(id:string):Promise<void>;
 StartInstall(id:string):Promise<void>;
 CancelInstall():Promise<void>;
 GetResult():Promise<Result>;
 PrepareTrust():Promise<Trust>;
 ApplyTrust(id:string,approved:boolean):Promise<{Detail:string}>;
 Verify():Promise<Result>;
 ExportRedactedReport():Promise<string>;
 EndSession():Promise<void>;
}

export class Wizard{
 step=0;prepared=false;busy=false;running=false;reviewed=false;message='';
 connection:Connection={Host:'192.168.1.1',Port:22,User:'admin',Password:''};
 selection:Selection={Cores:['mihomo'],ActiveCore:'mihomo',UI:true,Watchdog:false,ImportCore:'mihomo',ImportText:'',ProviderURL:''};
 inspection:Inspection|null=null;plan:Plan|null=null;hostKey:HostKey|null=null;result:Result|null=null;trust:Trust|null=null;
 progress:{Step:string;Status:string;Message:string}[]=[];
 constructor(readonly backend:Backend){}
 connectionChanged(){this.inspection=null;this.plan=null;this.reviewed=false;this.hostKey=null;}
 selectionChanged(){this.plan=null;this.reviewed=false;}
 next(){if(this.busy||this.running||this.step===0&&!this.prepared||this.step===1&&!this.inspection||this.step===2&&!this.inspection?.Entware||this.step>=5)return false;this.step++;return true;}
 async inspect(){
  if(this.busy||this.running)return;this.busy=true;this.message='';this.plan=null;this.reviewed=false;
  try{const v=await this.backend.Inspect({...this.connection});this.hostKey=v.HostKey??null;
   if(!this.hostKey){this.connection.Password='';this.inspection=v;this.step=2;if(['mihomo','xray'].includes(v.ActiveCore)){this.selection.ActiveCore=v.ActiveCore;this.selection.Cores=[v.ActiveCore];this.selection.ImportCore=v.ActiveCore;}}
  }catch{this.inspection=null;this.message='Проверка не завершена. Проверьте SSH, учётные данные и доступ к /opt.';this.connection.Password='';}
  finally{this.busy=false;}
 }
 async confirmHost(){if(this.hostKey?.Kind!=='first-use')return;await this.backend.ConfirmHostKey(this.hostKey.Address,this.hostKey.Fingerprint);this.hostKey=null;await this.inspect();}
 async prepare(){
  if(this.busy||this.running||!this.inspection)return;this.busy=true;this.reviewed=false;this.message='';
  try{this.plan=await this.backend.PreparePlan({...this.selection,InspectionID:this.inspection.ID});this.step=6;}
  catch{this.plan=null;this.message='План не подготовлен. Повторите проверку и проверьте конфигурацию.';}
  finally{this.busy=false;}
 }
 async start(){
  if(this.busy||this.running||!this.reviewed||!this.plan?.ID)return;this.busy=true;this.message='';
  const id=this.plan.ID;
  try{await this.backend.ConfirmPlan(id);this.running=true;this.step=7;await this.backend.StartInstall(id);this.connection.Password='';this.selection.ImportText='';this.selection.ProviderURL='';}
  catch{this.running=false;this.step=6;this.message='Запуск заблокирован. Повторите проверку и подтвердите новый план.';this.plan=null;this.reviewed=false;}
  finally{this.busy=false;}
 }
 async cancel(){await this.backend.CancelInstall();this.inspection=null;this.plan=null;this.reviewed=false;this.message='Отмена не откатывает выполненные записи. Дождитесь результата и повторите проверку.';}
 async finish(){this.result=await this.backend.GetResult();this.running=false;this.connection.Password='';this.selection.ImportText='';this.selection.ProviderURL='';this.inspection=null;this.plan=null;this.step=8;}
 async end(){await this.backend.EndSession();this.connection.Password='';this.selection.ImportText='';this.selection.ProviderURL='';this.inspection=null;this.plan=null;this.result=null;this.trust=null;this.reviewed=false;this.progress=[];this.message='';this.prepared=false;this.step=0;}
}
