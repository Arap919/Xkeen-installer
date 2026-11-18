export type HostKey={Kind:string;Address:string;Fingerprint:string;Expected:string;Algorithm:string};
export type Inspection={ID:string;Arch:string;Entware:boolean;Available:number;ActiveCore:string;Versions:Record<string,string>;HostKey?:HostKey|null};
export type Plan={ID:string;Steps:{ID:string;Description:string}[]|null;Changes:{Path:string;Action:string;Mode:string}[]|null;Artifacts:{Component:string;Version:string}[]|null;Dependencies:string[]|null;Notes:string[]|null;Files:{Path:string;Action:string;Preview:string}[]|null;Conflicts:{Path:string;Reason:string;NecessaryAddition:string}[]|null;Message:string};
export type Check={State:string;Detail:string};
export type Result={Status:string;Message:string;Backup?:string;Completed?:string[];Applied?:string[];Uncertain?:string;Pending?:string[];PanelURL?:string;Services:{Component:string;Process:Check;Configuration:Check;API:Check;HTTPS:Check;Trust:Check}[]|null};
export type Connection={Host:string;Port:number;User:string;Password:string};
export type Selection={Cores:string[];ActiveCore:string;UI:boolean;Watchdog:boolean;ImportCore:string;ImportText:string;ProviderURL:string;MihomoProviderURLs:string[];XrayProviderURLs:string[]};
export type Trust={ID:string;Description:string;Manual:string};
export type BootstrapVolume={UUID:string;Label:string;Free:number;Share:string;MediaID?:string};
export type BootstrapDiscovery={Model:string;Hardware:string;Arch:string;Volumes:BootstrapVolume[];HostKey?:HostKey|null};
export type BootstrapPlan={ID:string;Model:string;Hardware:string;Arch:string;Volume:BootstrapVolume;Archive:string;URL:string;SHA256:string;Size:number;Commands:string[];IntegritySource:string};
function inspectionMessage(error:unknown):string{
 const message=typeof error==='string'?error:error instanceof Error?error.message:'';
 const code=/^\[(SSH_[A-Z]+)\]/.exec(message)?.[1]??'';
 const messages:Record<string,string>={
  SSH_INPUT:'Проверьте адрес роутера, SSH-порт (1–65535) и логин.',
  SSH_CONNECT:'Не удалось подключиться к SSH. Проверьте адрес, доступность роутера и порт SSH Entware (обычно 222).',
  SSH_AUTH:'SSH не принял логин или пароль. Используйте учётную запись Entware (обычно root), а не пароль веб-панели Keenetic.',
  SSH_TIMEOUT:'Истекло время ожидания SSH или проверки роутера. Проверьте сеть и доступность SSH Entware, затем повторите проверку.',
  SSH_SHELL:'SSH подключён, но вместо shell доступен CLI KeeneticOS. Укажите порт SSH Entware (обычно 222) и его логин (обычно root); порт 22 часто открывает CLI KeeneticOS.',
  SSH_ARCH:'Архитектура роутера не поддерживается: нужны ARM64, MIPSel или MIPS.',
  SSH_INSPECT:'SSH подключён, но проверка Entware не завершена. Проверьте подключение накопителя, доступ к /opt и работу opkg в этой SSH-сессии.',
  SSH_INITRC:'Установка Entware ещё не подтверждена. Дождитесь завершения OPKG и проверьте в KeeneticOS Initrc /opt/etc/init.d/rc.unslung. Мастер также проверяет исполняемый файл по этому пути.',
 };
 return messages[code]??'Проверка не завершена. Проверьте SSH Entware, учётные данные и доступ к /opt.';
}
function bootstrapInspectionMessage(error:unknown):string{
 const message=typeof error==='string'?error:error instanceof Error?error.message:'';
 const code=/^\[((?:SSH|BOOTSTRAP)_[A-Z_]+)\]/.exec(message)?.[1]??'';
 const messages:Record<string,string>={
  SSH_INPUT:'Проверьте адрес роутера, SSH-порт и имя пользователя администратора KeeneticOS.',
  SSH_CONNECT:'Не удалось подключиться к SSH KeeneticOS. Проверьте адрес и порт (обычно 22).',
  SSH_AUTH:'SSH KeeneticOS отклонил учётные данные администратора. Проверьте логин admin, пароль и разрешение SSH для этой учётной записи. Терминал мог использовать ключ вместо пароля.',
  SSH_TIMEOUT:'Истекло время ожидания SSH KeeneticOS. Проверьте доступность роутера и порт 22.',
  BOOTSTRAP_VERSION:'SSH подключён, но команда show version не завершилась. Нужно проверить совместимость CLI KeeneticOS с мастером.',
  BOOTSTRAP_MEDIA:'SSH подключён, но команда show media не завершилась. Нужно проверить доступность команды в CLI KeeneticOS.',
  BOOTSTRAP_CIFS:'SSH подключён, но команда show cifs не завершилась. Нужна проверка обмена с CLI KeeneticOS.',
  BOOTSTRAP_CIFS_PARSE:'Команда show cifs выполнена, но разбор её ответа завершился ошибкой установщика. Неактивные ресурсы прежних накопителей не используются; настройки SMB наугад менять не нужно.',
  BOOTSTRAP_CONFIG:'SSH подключён, но команда show running-config не завершилась. Нужно проверить права администратора и CLI KeeneticOS.',
  BOOTSTRAP_PARSE:'Команды CLI выполнены, но мастер не смог безопасно разобрать модель, разделы или настройки OPKG/SMB. Нужны модель, версия KeeneticOS и вывод show version / show media; полную конфигурацию отправлять не нужно.',
  BOOTSTRAP_TARGET:'Не найден подходящий EXT4-раздел: нужен смонтированный накопитель, минимум 64 МиБ свободного места и SMB-ресурс его корня. Другой OPKG-диск или пользовательский Initrc блокирует новую установку.',
  BOOTSTRAP_SMB:'SSH и CLI проверены. Не удалось подключиться к SMB с обязательной подписью: проверьте компонент SMB, доступ по порту 445 и права этой учётной записи. Проверка корня EXT4 выполняется при подготовке плана.',
 };
 const diagnostic=code==='BOOTSTRAP_CIFS_PARSE'?/\bCIFS\/(TEXT|CONTROL|VALUE|MISSING|DUPLICATE|CONTEXT|UNKNOWN_FIELD|NAME_CONFLICT|ROOT_CONFLICT|SCHEMA)\/([0-9]{1,7})\/(none|unknown|share|enabled|automount|permissive|map-hidden|master|mount|label|active|description)\b/.exec(message):null;
 const suffix=diagnostic?` Диагностика: ${diagnostic[0]}.`:'';
 return messages[code]?`[${code}] ${messages[code]}${suffix}`:'Проверка KeeneticOS не завершена: получена нераспознанная ошибка установщика. Пароль и конфигурация в сообщении скрыты.';
}
function planMessage(error:unknown):string{
 const raw=typeof error==='string'?error:error instanceof Error?error.message:'';
 const fallback='[PLAN/UNEXPECTED] Не удалось подготовить план: нераспознанная ошибка установщика.';
 const planMessages:Record<string,string>={
  '[PLAN/STATE/BUSY]':'Подготовка плана недоступна: установщик занят.',
  '[PLAN/INSPECTION/STALE]':'Результат проверки роутера устарел. Повторите проверку перед подготовкой плана.',
  '[PLAN/TLS/STORAGE_PATH]':'Не удалось определить путь локального хранилища TLS.',
  '[PLAN/TLS/PREPARE]':'Подготовка TLS для плана завершилась ошибкой.',

  "[PLAN/INPUT/FILE_SIZE]": "Локальный файл превышает 2 МиБ.",
  "[PLAN/INPUT/MIXED_SOURCES]": "Одновременно выбраны локальный файл и подписки.",
  "[PLAN/INPUT/DUPLICATE]": "Подписка Mihomo указана одновременно в двух полях.",
  "[PLAN/CONFIGURATION/CORE_SELECTION]": "Выбрано неподдерживаемое ядро.",
  "[PLAN/CONFIGURATION/NO_CORE]": "Не выбрано ни одного ядра.",
  "[PLAN/CONFIGURATION/IMPORT_SIZE]": "Размер импортируемой конфигурации превышает предел.",
  "[PLAN/CONFIGURATION/IMPORT_CORE]": "Ядро импортируемой конфигурации не выбрано.",
  "[PLAN/CONFIGURATION/PROVIDER_SOURCE]": "Источник подписки Mihomo несовместим с выбранным импортом.",
  "[PLAN/CONFIGURATION/XRAY_INPUT]": "Подготовленные данные подписки Xray некорректны.",
  "[PLAN/CONFIGURATION/ACTIVE_CORE]": "Активное ядро отсутствует среди выбранных.",
  "[PLAN/CONFIGURATION/SNAPSHOT]": "Содержимое конфигурации из проверки роутера недоступно.",
  "[PLAN/CONFIGURATION/MIHOMO_SIZE]": "Размер конфигурации Mihomo недопустим.",
  "[PLAN/CONFIGURATION/MIHOMO_YAML]": "Конфигурация Mihomo не является корректным YAML-объектом.",
  "[PLAN/CONFIGURATION/YAML_DOCUMENTS]": "Конфигурация содержит несколько YAML-документов.",
  "[PLAN/CONFIGURATION/XRAY_SIZE]": "Размер конфигурации Xray недопустим.",
  "[PLAN/CONFIGURATION/XRAY_JSON]": "Конфигурация Xray не является корректным JSON-объектом.",
  "[PLAN/CONFIGURATION/API_SECRET]": "Не удалось создать API-секрет конфигурации.",
  "[PLAN/CONFIGURATION/EMBEDDED_PROVIDERS]": "Во встроенном шаблоне отсутствует раздел proxy-providers.",
  "[PLAN/CONFIGURATION/EMBEDDED_PROVIDER]": "Во встроенном шаблоне отсутствует VPNProvider.",
  "[PLAN/CONFIGURATION/INTERNAL]": "Подготовка конфигурации завершилась внутренней ошибкой установщика."
};
 const tlsOperations:Record<string,string>={LOAD_STORE:'Чтение существующего локального хранилища сертификатов',GENERATE:'Проверка или создание сертификата панели',BASE_DIRECTORY:'Создание каталога приложения для сертификатов',MATERIAL:'Подготовка материала сертификата',LOCATION:'Подготовка каталога хранения ключей',OPEN_STORE:'Открытие защищённого хранилища',CHECK_EXISTING:'Проверка существующих файлов сертификатов',CREATE_FILE:'Создание файла сертификата или ключа',WRITE_FILE:'Запись файла сертификата или ключа',SYNC_FILE:'Сохранение файла на диск',SYNC_STORE:'Сохранение хранилища на диск',READBACK:'Контрольное чтение сохранённых файлов',PUBLISH_STORE:'Публикация каталога сертификатов Windows',WINDOWS_TOKEN:'Получение текущей учётной записи Windows',WINDOWS_DACL_BUILD:'Создание правил доступа Windows',WINDOWS_DACL_SET:'Установка закрытых прав доступа Windows',WINDOWS_DACL_READ:'Чтение прав доступа Windows',WINDOWS_DACL_COMPARE:'Проверка закрытых прав доступа Windows'};
 const tlsOperation=/^\[PLAN\/TLS\/([A-Z_]+)\]$/.exec(raw)?.[1];
 if(tlsOperation&&Object.prototype.hasOwnProperty.call(tlsOperations,tlsOperation))return `${raw} ${tlsOperations[tlsOperation]}: операция не завершена.`;
 if(Object.prototype.hasOwnProperty.call(planMessages,raw))return `${raw} ${planMessages[raw]}`;
 if(raw==='[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0]')return '[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0] Подготовка подписок завершилась внутренней ошибкой установщика.';
 const match=/^\[SUBSCRIPTION\/(MIHOMO|XRAY)\/(URL|FETCH|JSON|MERGE|SELECTION)\/([A-Z_]+)\/(0|[1-9][0-9]?)\/(0|[1-5][0-9]{2})\]$/.exec(raw);
 if(!match)return fallback;
 const [,core,stage,code,indexText,statusText]=match;const index=Number(indexText),status=Number(statusText);
 const messages:Record<string,string>={
  "URL/COUNT": "Количество ссылок превышает предел 10.",
  "URL/EMPTY": "Ссылка пуста.",
  "URL/LENGTH": "Длина ссылки превышает 8192 байта.",
  "URL/CONTROL": "Ссылка содержит управляющий символ.",
  "URL/WHITESPACE": "Ссылка содержит пробельный символ.",
  "URL/PARSE": "Синтаксис ссылки некорректен.",
  "URL/HTTP": "Ссылка использует HTTP. Требуется HTTPS.",
  "URL/SCHEME": "Схема ссылки не поддерживается. Требуется HTTPS.",
  "URL/HOST": "В ссылке отсутствует имя сервера.",
  "URL/USERINFO": "Ссылка содержит встроенные учётные данные.",
  "URL/FRAGMENT": "Ссылка содержит фрагмент после #.",
  "FETCH/REQUEST": "Не удалось создать запрос подписки.",
  "FETCH/TIMEOUT": "Истекло время ожидания загрузки подписки.",
  "FETCH/CANCELED": "Загрузка подписки отменена.",
  "FETCH/DNS": "Не удалось разрешить имя сервера подписки через DNS.",
  "FETCH/TLS": "Ошибка TLS при загрузке подписки.",
  "FETCH/CONNECTION": "Не удалось установить соединение с сервером подписки.",
  "FETCH/REDIRECT": "Перенаправление подписки отклонено.",
  "FETCH/HTTP_STATUS": "",
  "FETCH/BODY_READ": "Не удалось прочитать тело ответа подписки.",
  "FETCH/SIZE": "Размер ответа подписки превышает 2 МиБ.",
  "FETCH/TRANSPORT": "Загрузка подписки завершилась ошибкой транспорта.",
  "JSON/SIZE": "Размер JSON подписки превышает 2 МиБ.",
  "JSON/SYNTAX": "Синтаксис JSON подписки некорректен.",
  "JSON/DOCUMENT": "Документ подписки не является JSON-объектом.",
  "JSON/OUTBOUNDS": "В документе подписки отсутствует массив outbounds.",
  "JSON/OUTBOUND": "Элемент outbounds не является объектом.",
  "JSON/SETTINGS": "У прокси отсутствует объект settings.",
  "MERGE/DEPENDENCY": "Прокси содержит неподдерживаемую зависимую цепочку.",
  "MERGE/NO_PROXY": "Подписка не содержит подходящего прокси.",
  "MERGE/OUTPUT_LIMIT": "Объединённая конфигурация превышает 2 МиБ.",
  "SELECTION/CORE_MISSING": "Ядро для этой подписки не выбрано."
};
 messages['FETCH/HTTP_STATUS']=`Сервер подписки вернул HTTP ${status}.`;
 const key=`${stage}/${code}`,detail=messages[key];
 if(!detail||index>11||core==='MIHOMO'&&stage!=='URL'&&stage!=='SELECTION')return fallback;
 if(index===11&&key!=='URL/COUNT'||key==='URL/COUNT'&&index!==11)return fallback;
 if(code==='HTTP_STATUS'?(status<100||status>599||index<1||index>10):status!==0)return fallback;
 if(index===0&&!(core==='XRAY'&&stage==='MERGE'&&(code==='OUTPUT_LIMIT'||code==='NO_PROXY')))return fallback;
 const stages:Record<string,string>={URL:'проверка ссылки',FETCH:'загрузка',JSON:'разбор JSON',MERGE:'сборка конфигурации',SELECTION:'выбор ядра'};
 return `${raw} ${core==='MIHOMO'?'Mihomo':'Xray'}${index>0?`, подписка №${index}`:''}: ${stages[stage]}. ${detail}`;
}

export interface Backend{
 DiscoverBootstrap?(c:Connection):Promise<BootstrapDiscovery>;
 PrepareBootstrap?(uuid:string,password:string,repeat:string):Promise<BootstrapPlan>;
 StartBootstrap?(id:string,reviewed:boolean):Promise<void>;
 Inspect(c:Connection):Promise<Inspection>;
 ConfirmHostKey(address:string,fingerprint:string):Promise<void>;
 PreparePlan(r:Selection&{InspectionID:string}):Promise<Plan>;
 ConfirmPlan(id:string):Promise<void>;
 StartInstall(id:string):Promise<void>;
 CancelInstall():Promise<void>;
 GetResult():Promise<Result>;
 PrepareTrust():Promise<Trust>;
 ApplyTrust(id:string,approved:boolean):Promise<{Status?:string;Detail:string;Code?:string}>;
 Verify():Promise<Result>;
 ExportRedactedReport():Promise<string>;
 EndSession():Promise<void>;
}

export class Wizard{
 mode:'new'|'existing'='existing';bootstrap:BootstrapDiscovery|null=null;bootstrapPlan:BootstrapPlan|null=null;bootstrapUUID='';bootstrapPassword='';bootstrapPasswordRepeat='';bootstrapReviewed=false;bootstrapWaiting=false;
 completionBusy=false;private completionStarted=false;
 step=0;prepared=false;busy=false;running=false;reviewed=false;message='';
 connection:Connection={Host:'192.168.1.1',Port:222,User:'root',Password:''};
 selection:Selection={Cores:['mihomo'],ActiveCore:'mihomo',UI:true,Watchdog:false,ImportCore:'mihomo',ImportText:'',ProviderURL:'',MihomoProviderURLs:[],XrayProviderURLs:[]};
 inspection:Inspection|null=null;plan:Plan|null=null;hostKey:HostKey|null=null;result:Result|null=null;trust:Trust|null=null;
 progress:{Step:string;Status:string;Message:string}[]=[];
 private finishedEvents=new Set<string>();
 private resetProgress(){this.progress=[];this.finishedEvents.clear();this.completionStarted=false;}
 async receiveProgress(event:{Step:string;Status:string;Message:string}){
  if(event.Step==='finished'||event.Step==='bootstrap-finished'){
   if(this.finishedEvents.has(event.Step))return;
   this.finishedEvents.add(event.Step);
   if(event.Step==='finished')await this.finish();else await this.finishBootstrap();
   return;
  }
  if(this.mode==='new'&&event.Status==='running'){
   const order=['reinspect','download','transfer','credential-transfer','credential-check','trigger','waiting-shell'];
   const next=order.indexOf(event.Step);
   if(next>=0){
    const latest=Math.max(-1,...this.progress.map(stage=>order.indexOf(stage.Step)));
    if(next<latest)return;
    for(const stage of this.progress){
     const previous=order.indexOf(stage.Step);
     if(previous>=0&&previous<next&&stage.Status==='running')stage.Status='completed';
    }
   }
  }
  const current=this.progress.find(stage=>stage.Step===event.Step);
  if(current){if(current.Status==='completed'&&event.Status==='running')return;Object.assign(current,event);}
  else this.progress.push({...event});
 }

 constructor(readonly backend:Backend){}
 setMode(mode:'new'|'existing'){this.mode=mode;this.connection.Port=mode==='new'?22:222;this.connection.User=mode==='new'?'admin':'root';this.connection.Password='';this.connectionChanged();this.bootstrapWaiting=false;}
 connectionChanged(){this.clearBootstrapPasswords();this.inspection=null;this.plan=null;this.reviewed=false;this.hostKey=null;this.bootstrap=null;this.bootstrapPlan=null;this.bootstrapReviewed=false;this.bootstrapUUID='';}
 clearSubscriptions(){this.selection.ProviderURL='';this.selection.MihomoProviderURLs=[];this.selection.XrayProviderURLs=[];}
 clearSensitiveInputs(){this.clearBootstrapPasswords();this.connection.Password='';this.selection.ImportText='';this.clearSubscriptions();}
 selectionChanged(){this.plan=null;this.reviewed=false;this.selection.ProviderURL='';if(!this.selection.Cores.includes('mihomo'))this.selection.MihomoProviderURLs=[];if(!this.selection.Cores.includes('xray'))this.selection.XrayProviderURLs=[];}
 next(){if(this.busy||this.running||this.step===0&&!this.prepared||this.step===1&&!this.inspection||this.step===2&&!this.inspection?.Entware||this.step>=5)return false;this.step++;return true;}
 async inspect(){
  if(this.busy||this.running)return;this.busy=true;this.message='';this.plan=null;this.reviewed=false;
  if(this.mode==='new'){
   try{if(!this.backend.DiscoverBootstrap)throw new Error();const v=await this.backend.DiscoverBootstrap({...this.connection});this.hostKey=v.HostKey??null;if(!this.hostKey){this.connection.Password='';this.bootstrap=v;this.bootstrapUUID=v.Volumes.length===1?v.Volumes[0].UUID:'';this.step=2;}}
   catch(error){this.bootstrap=null;this.connection.Password='';this.message=bootstrapInspectionMessage(error);}
   finally{this.busy=false;}return;
  }
  try{const v=await this.backend.Inspect({...this.connection});this.hostKey=v.HostKey??null;
   if(!this.hostKey){this.connection.Password='';this.inspection=v;this.step=2;if(['mihomo','xray'].includes(v.ActiveCore)){this.selection.ActiveCore=v.ActiveCore;this.selection.Cores=[v.ActiveCore];this.selection.ImportCore=v.ActiveCore;}}
  }catch(error){this.inspection=null;this.message=inspectionMessage(error);this.connection.Password='';}
  finally{this.busy=false;}
 }
 async confirmHost(){if(this.hostKey?.Kind!=='first-use')return;await this.backend.ConfirmHostKey(this.hostKey.Address,this.hostKey.Fingerprint);this.hostKey=null;await this.inspect();}
 private clearBootstrapPasswords(){this.bootstrapPassword='';this.bootstrapPasswordRepeat='';}
 bootstrapPasswordChanged(){this.bootstrapPlan=null;this.bootstrapReviewed=false;}
 async prepareBootstrap(){
  if(this.busy||this.running||!this.bootstrap||!this.bootstrapUUID)return;
  this.busy=true;this.bootstrapPlan=null;this.bootstrapReviewed=false;this.message='';
  try{
   const password=this.bootstrapPassword,repeat=this.bootstrapPasswordRepeat;
   const invalidUnicode=[...password].some(character=>{const point=character.codePointAt(0)!;return point>=0xd800&&point<=0xdfff;});
   if(password!==repeat||[...password].length<16||new TextEncoder().encode(password).length>1024||/[\0\r\n]/.test(password)||invalidUnicode){this.message='Пароли должны совпадать: минимум 16 символов, максимум 1024 байта UTF-8, без NUL и переводов строк.';return;}
   if(!this.backend.PrepareBootstrap)throw new Error();
   this.bootstrapPlan=await this.backend.PrepareBootstrap(this.bootstrapUUID,password,repeat);
  }catch{this.bootstrapPlan=null;this.message='План Entware заблокирован. Нужен корневой SMB-ресурс EXT4, свободное место и отсутствие существующего Entware, другого OPKG-диска, чужого архива или пользовательского initrc.';}
  finally{this.clearBootstrapPasswords();this.busy=false;}
 }
 async startBootstrap(){if(this.busy||this.running||!this.bootstrapReviewed||!this.bootstrapPlan?.ID)return;this.resetProgress();this.busy=true;this.running=true;this.message='';try{if(!this.backend.StartBootstrap)throw new Error();await this.backend.StartBootstrap(this.bootstrapPlan.ID,true);this.connection.Password='';this.bootstrapPlan=null;this.bootstrapReviewed=false;}catch{this.running=false;this.bootstrapPlan=null;this.bootstrapReviewed=false;this.message='Запуск Entware заблокирован. Повторите проверку и подготовьте новый план.';}finally{this.busy=false;}}
 async finishBootstrap(){this.clearBootstrapPasswords();this.result=await this.backend.GetResult();this.running=false;this.bootstrapWaiting=true;this.connection.Password='';this.bootstrapPlan=null;this.bootstrapReviewed=false;this.message=this.result.Message;this.step=2;}
 connectShell(){const host=this.connection.Host;this.setMode('existing');this.connection.Host=host;this.step=1;this.message='Дождитесь завершения OPKG, проверьте Initrc /opt/etc/init.d/rc.unslung в KeeneticOS и укажите текущие данные SSH Entware. Новый SSH-ключ подтверждается отдельно.';}
 async prepare(){
  if(this.busy||this.running||!this.inspection)return;this.busy=true;this.reviewed=false;this.message='';
  const urls=(core:string,values:string[])=>this.selection.Cores.includes(core)?values.map(value=>value.trim()).filter(Boolean):[];
  try{this.plan=await this.backend.PreparePlan({...this.selection,MihomoProviderURLs:urls('mihomo',this.selection.MihomoProviderURLs),XrayProviderURLs:urls('xray',this.selection.XrayProviderURLs),InspectionID:this.inspection.ID});this.step=6;}
  catch(error){this.plan=null;this.message=planMessage(error);}
  finally{this.busy=false;}
 }
 async start(){
  if(this.busy||this.running||!this.reviewed||!this.plan?.ID)return;this.busy=true;this.message='';
  const id=this.plan.ID;this.resetProgress();this.clearSensitiveInputs();
  try{await this.backend.ConfirmPlan(id);this.running=true;this.step=7;await this.backend.StartInstall(id);}
  catch{this.running=false;this.step=6;this.message='Запуск заблокирован. Повторите проверку и подтвердите новый план.';this.plan=null;this.reviewed=false;}
  finally{this.busy=false;}
 }
 async cancel(){await this.backend.CancelInstall();this.inspection=null;this.plan=null;this.reviewed=false;this.message='Отмена не откатывает выполненные записи. Дождитесь результата и повторите проверку.';}
 async finish(){this.clearSensitiveInputs();this.result=await this.backend.GetResult();this.running=false;this.inspection=null;this.plan=null;this.step=8;}

 private uiService(){return this.result?.Services?.find(service=>service.Component==='ui');}
 private uiReady(){const ui=this.uiService();return !!ui&&ui.API.State==='passed'&&ui.HTTPS.State==='passed'&&ui.Trust.State==='passed';}
 private canOfferTrust(){const ui=this.uiService();return this.result?.Status==='installed'&&!!ui&&ui.API.State==='passed'&&ui.HTTPS.State==='passed'&&ui.Trust.State!=='passed';}
 private pendingTrustMessage(){return 'Компоненты установлены. Системное доверие CA ещё не подтверждено. Повторите настройку доверия CA.';}
 private verificationMessage(){
  const ui=this.uiService();
  if(!ui)return 'Компоненты установлены. В отчёте нет проверки UI; настройка доверия CA недоступна.';
  if(ui.HTTPS.State!=='passed')return 'Компоненты установлены. Ожидаемый HTTPS панели не подтверждён. Повторите проверку служб.';
  if(ui.API.State!=='passed')return 'Компоненты установлены. API панели не подтверждён. Повторите проверку служб.';
  if(ui.Trust.State!=='passed')return this.pendingTrustMessage();
  return 'Компоненты установлены. HTTPS, API панели и системное доверие CA проверены.';
 }
 private async refreshVerification(){
  if(this.result)this.result.PanelURL='';
  this.result=await this.backend.Verify();
  if(!this.uiReady()&&this.result)this.result.PanelURL='';
  if(this.uiService()&&this.result)this.result.Message=this.verificationMessage();
 }
 private caFailure(stage:'VERIFY'|'PREPARE'|'IMPORT'){
  const messages={VERIFY:'Не удалось завершить проверку панели. Повторите проверку служб.',PREPARE:'Не удалось подготовить сведения об этом CA. Повторите настройку доверия CA.',IMPORT:'Не удалось выполнить установку CA. Повторите настройку доверия CA.'};
  return `[CA/${stage}] ${messages[stage]} Компоненты установлены.`;
 }
 async completeUISetup(){
  if(this.completionStarted||this.completionBusy||this.running||this.step!==8||this.result?.Status!=='installed'||!this.selection.UI)return;
  this.completionStarted=true;this.completionBusy=true;this.message='';let stage:'VERIFY'|'PREPARE'='VERIFY';
  try{await this.refreshVerification();if(this.canOfferTrust()){stage='PREPARE';this.trust=await this.backend.PrepareTrust();}}
  catch{this.message=this.caFailure(stage);}finally{this.completionBusy=false;}
 }
 async verifyInstalled(){
  if(this.busy||this.completionBusy||this.running||this.result?.Status!=='installed')return;
  this.completionBusy=true;this.message='';
  try{await this.refreshVerification();}catch{this.message=this.caFailure('VERIFY');}finally{this.completionBusy=false;}
 }
 async prepareTrust(){
  if(this.busy||this.completionBusy||this.running||this.trust||this.result?.Status!=='installed'||!this.selection.UI)return;
  this.completionBusy=true;this.message='';let stage:'VERIFY'|'PREPARE'='VERIFY';
  try{await this.refreshVerification();if(this.canOfferTrust()){stage='PREPARE';this.trust=await this.backend.PrepareTrust();}else this.message=this.verificationMessage();}
  catch{this.message=this.caFailure(stage);}finally{this.completionBusy=false;}
 }
 rejectTrust(){if(this.completionBusy)return;this.trust=null;this.message=this.pendingTrustMessage();}
 async applyTrust(){
  if(this.busy||this.completionBusy||this.running||!this.trust?.ID||!this.canOfferTrust()||this.result?.Status!=='installed')return;
  const id=this.trust.ID;this.completionBusy=true;this.trust=null;this.message='';let stage:'IMPORT'|'VERIFY'='IMPORT';
  try{const command=await this.backend.ApplyTrust(id,true);this.message=command.Detail;stage='VERIFY';await this.refreshVerification();this.message=this.uiReady()?this.verificationMessage():`${command.Detail} ${this.verificationMessage()}`;}
  catch{this.message=this.caFailure(stage);}finally{this.completionBusy=false;}
 }
 async end(){this.clearSensitiveInputs();await this.backend.EndSession();this.bootstrap=null;this.bootstrapPlan=null;this.bootstrapWaiting=false;this.bootstrapReviewed=false;this.inspection=null;this.plan=null;this.result=null;this.trust=null;this.reviewed=false;this.resetProgress();this.message='';this.prepared=false;this.step=0;}
}
