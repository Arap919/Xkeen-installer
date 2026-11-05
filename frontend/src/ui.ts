import {Wizard,type Check} from './wizard';
const steps=['Подготовка','Подключение','Проверка роутера','Ядра','Компоненты','Конфигурация','План изменений','Установка','Результат'];
const escape=(value:unknown)=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const field=(id:string,label:string,value:string|number,type='text')=>`<label for="${id}">${label}<input id="${id}" type="${type}" value="${escape(value)}" autocomplete="off"></label>`;
const states:Record<string,string>={passed:'Подтверждено',failed:'Не подтверждено',pending:'Ожидает проверки','not-applicable':'Не требуется',unconfigured:'Нужна настройка','matched-reviewed-plan':'Соответствует плану'};
const stageTitle=(id:string)=>({download:'Загрузка и проверка артефактов',reinspect:'Повторная проверка роутера',backup:'Резервная копия',dependencies:'Установка зависимостей',stop:'Остановка служб',install:'Установка компонентов',configure:'Сохранение конфигураций',validate:'Проверка конфигураций',activate:'Запуск активного ядра',watchdog:'Настройка watchdog',tls:'Проверка TLS',ui:'Запуск панели',preservation:'Проверка сохранности настроек',finished:'Завершение'} as Record<string,string>)[id]??id;
const check=(c:Check)=>`<span class="state ${escape(c.State)}">${escape(states[c.State]??c.State)}</span><small>${escape(c.Detail)}</small>`;

export function mount(root:HTMLElement,w:Wizard){
 let exported='';
 function screen():string {
  switch(w.step){
  case 0:return `<p class="lead">Установите XKeen и панель управления, сохранив настройки роутера.</p><h2>Подготовьте Keenetic</h2><ol class="preparation"><li>Установите нужные компоненты KeeneticOS и подготовьте накопитель.</li><li>Самостоятельно выберите накопитель OPKG и включите SSH с доступом к POSIX shell.</li><li>Проверьте DNS и политики клиентов. При необходимости измените порт управления и создайте RCI-токен вручную.</li></ol><aside>Мастер не форматирует диск, не меняет настройки KeeneticOS и не перезагружает роутер. Entware должен быть подготовлен штатным механизмом OPKG.</aside><label class="check"><input id="prepared" type="checkbox" ${w.prepared?'checked':''}>Подготовка выполнена, накопитель подключён</label>`;
  case 1:return `<p>Используйте адрес роутера в вашей сети. Пароль нужен только для текущего SSH-подключения.</p><div class="form-grid">${field('host','Адрес роутера',w.connection.Host)}${field('port','SSH-порт',w.connection.Port,'number')}${field('user','Имя пользователя',w.connection.User)}${field('password','Пароль SSH',w.connection.Password,'password')}</div><aside>Перед первым подключением отдельно сравните отпечаток ключа SSH. Неожиданная замена известного ключа блокируется. Подтверждённый ключ хранится только до закрытия приложения.</aside><p class="muted">SMB-передача до Entware не подтверждена. Если Entware отсутствует, используйте ручную подготовку OPKG и повторную проверку.</p><button data-action="inspect" ${w.busy?'disabled':''}>Проверить роутер</button>`;
  case 2:{const s=w.inspection;return s?`<p class="lead">${s.Entware?'Entware обнаружен':'Entware не установлен'}</p><dl><dt>Архитектура</dt><dd>${escape(s.Arch)}</dd><dt>Свободное место</dt><dd>${(s.Available/1048576).toFixed(0)} МиБ</dd><dt>Активное ядро</dt><dd>${escape(s.ActiveCore)}</dd></dl><h2>Обнаруженные версии</h2><ul>${Object.entries(s.Versions).map(([name,version])=>`<li>${escape(name)} <strong>${escape(version)}</strong></li>`).join('')}</ul>${!s.Entware?'<aside>Подготовьте Entware через OPKG вручную, затем повторите проверку. Мастер не выдаёт копирование архива за завершённую установку.</aside>':''}<p class="muted">Проверка актуальна 5 минут. Перед записью backend снова сравнит фактическое состояние.</p>`:'<p>Повторите подключение и проверку.</p>';}
  case 3:return `<p>Выберите ядра. При двух ядрах запускается только выбранное активное ядро.</p><div class="choices">${[['mihomo','Mihomo','YAML, подписки и группы Clash'],['xray','Xray','JSON, соединения и маршрутизация Xray'],['both','Mihomo и Xray','Оба установлены, одно активно']].map(([value,title,desc])=>`<label><input type="radio" name="cores" value="${value}" ${(value==='both'?w.selection.Cores.length===2:w.selection.Cores.length===1&&w.selection.Cores[0]===value)?'checked':''}><span><strong>${title}</strong><small>${desc}</small></span></label>`).join('')}</div><label>Активное ядро<select id="active">${w.selection.Cores.map(c=>`<option ${c===w.selection.ActiveCore?'selected':''}>${c}</option>`).join('')}</select></label><aside>Существующее активное ядро сохраняется по умолчанию. Переключение требует согласованного плана. Для запуска нового Xray импортируйте полностью настроенный JSON.</aside>`;
  case 4:return `<label class="check"><input id="ui" type="checkbox" ${w.selection.UI?'checked':''}>XKeen UI PWA: панель по HTTPS</label><p>Существующие данные панели и корректные сертификаты сохраняются. Новый CA остаётся в закрытом хранилище на компьютере.</p><label class="check"><input id="watchdog" type="checkbox" ${w.selection.Watchdog?'checked':''} ${w.selection.ActiveCore!=='mihomo'?'disabled':''}>router-watchdog: автоматическая проверка узлов Mihomo</label><p>Watchdog работает только с активным совместимым Mihomo: нужны provider-backed группы PROXY/BENCHMARK, API secret, HTTP listener и проверенный cron. Для активного Xray он недоступен.</p>`;
  case 5:return `<p>Существующие конфигурации сохраняются без перезаписи. Для новой установки выберите локальный файл или укажите подписку Mihomo для встроенного шаблона.</p><label>Ядро для импорта<select id="import-core">${w.selection.Cores.map(c=>`<option ${c===w.selection.ImportCore?'selected':''}>${c}</option>`).join('')}</select></label><label>Локальный YAML / JSON (до 2 МиБ)<input id="import-file" type="file" accept=".yaml,.yml,.json"></label><p class="muted">${w.selection.ImportText?'Локальная конфигурация прочитана; содержимое не включается в журнал.':'Файл не выбран. Существующие настройки будут использованы автоматически.'}</p>${field('provider','Подписка Mihomo (HTTPS)',w.selection.ProviderURL,'password')}<p class="muted">URL подписки считается секретом. Он не сохраняется в browser storage и не выводится в отчёт.</p><button data-action="prepare" ${w.busy?'disabled':''}>Подготовить план</button>`;
  case 6:{const p=w.plan;return p?`${p.Message?`<aside class="warning">${escape(p.Message)}</aside>`:''}${p.Conflicts?.length?`<h2>Требует согласования</h2><p>Неоднозначное слияние блокирует установку. Согласуйте конфигурацию вручную и повторите проверку.</p>${p.Conflicts.map(c=>`<details><summary>${escape(c.Path||'Конфигурация')}</summary><p>${escape(c.Reason)}</p>${c.NecessaryAddition?`<pre>${escape(c.NecessaryAddition)}</pre>`:''}</details>`).join('')}`:''}<h2>Версии и изменения</h2><p>${(p.Artifacts??[]).map(a=>`${escape(a.Component)} ${escape(a.Version)}`).join(', ')||'Готовый план пока отсутствует'}</p><ul class="changes">${(p.Changes??[]).map(c=>`<li><code>${escape(c.Path)}</code><span>${escape(c.Action)}</span><small>Права: ${escape(c.Mode)}</small></li>`).join('')}</ul><details><summary>Последовательность и зависимости</summary><ol>${(p.Steps??[]).map(s=>`<li>${escape(s.Description)}</li>`).join('')}</ol><p>${escape((p.Dependencies??[]).join(', '))}</p></details><p>Закрытая резервная копия создаётся и проверяется до изменения пакетов и служб. При ошибке копирования или нехватке места установка останавливается.</p>${(p.Notes??[]).map(n=>`<p class="muted">${escape(n)}</p>`).join('')}<label class="check"><input id="reviewed" type="checkbox" ${w.reviewed?'checked':''} ${!p.ID?'disabled':''}>Я просмотрел конкретный план и разрешаю перечисленные изменения на роутере</label><button data-action="start" ${!p.ID||!w.reviewed||w.busy?'disabled':''}>Установить по этому плану</button>`:'<p>Вернитесь к конфигурации и подготовьте план.</p>';}
  case 7:return `<p class="lead">Выполняется подтверждённый план</p><p>Не отключайте роутер и накопитель. Отмена останавливает дальнейшие этапы, но не откатывает завершённые записи.</p><ol class="progress" aria-live="polite">${w.progress.map(p=>`<li><strong>${escape(stageTitle(p.Step))}</strong><span>${escape(p.Status==='completed'?'Завершено':p.Status==='running'?'Выполняется':p.Message)}</span></li>`).join('')}</ol><button class="secondary" data-action="cancel">Остановить дальнейшие этапы</button>`;
  case 8:{const r=w.result;return `<p class="lead">${escape(r?.Message)}</p>${r?.Backup?`<p>Резервная копия: <code>${escape(r.Backup)}</code></p>`:''}${r?.Uncertain?`<aside>Неподтверждённый этап: ${escape(r.Uncertain)}. Повторите проверку состояния.</aside>`:''}<ul>${(r?.Pending??[]).map(p=>`<li>${escape(p)}</li>`).join('')}</ul>${r?.Status==='installed'?'<div class="actions"><button data-action="verify">Проверить службы и HTTPS</button><button class="secondary" data-action="trust">Просмотреть установку доверия CA</button></div>':''}${r?.PanelURL?`<p>Панель: <code>${escape(r.PanelURL)}</code></p>`:''}${r?.Services?.length?`<div class="table-wrap"><table><thead><tr><th>Служба</th><th>Процесс</th><th>Настройки</th><th>API</th><th>HTTPS</th><th>Доверие</th></tr></thead><tbody>${r.Services.map(s=>`<tr><th>${escape(s.Component)}</th>${[s.Process,s.Configuration,s.API,s.HTTPS,s.Trust].map(c=>`<td>${check(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:''}<p>Системное доверие CA подтверждается отдельно. На других устройствах установите только публичный сертификат CA вручную.</p><button class="secondary" data-action="export">Показать обезличенный отчёт</button>${exported?`<label>Отчёт для копирования<textarea readonly rows="12">${escape(exported)}</textarea></label>`:''}<button data-action="end">Новая проверка</button>`;}
  default:return '';
  }
 }
 function render(){
  root.innerHTML=`<div class="shell"><nav aria-label="Шаги установки"><div class="brand">XKeen<span>Установка и настройка</span></div><ol>${steps.map((s,i)=>`<li class="${i===w.step?'current':i<w.step?'done':''}" ${i===w.step?'aria-current="step"':''}><span>${i+1}</span>${s}</li>`).join('')}</ol><p>Настройки сохраняются.<br>Каждая запись — по плану.</p></nav><main><header><span>Шаг ${w.step+1} из 9</span><h1>${steps[w.step]}</h1></header><section>${screen()}${w.message?`<p class="error" role="alert">${escape(w.message)}</p>`:''}</section><footer><button class="secondary" data-action="back" ${w.step===0||w.running||w.busy?'disabled':''}>Назад</button><span>${w.busy?'Выполняется проверка…':w.running?'Установка в процессе':'Роутер изменяется только после подтверждения плана'}</span>${w.step<5?`<button data-action="next" ${w.busy||w.step===0&&!w.prepared||w.step===1&&!w.inspection||w.step===2&&!w.inspection?.Entware?'disabled':''}>Далее</button>`:''}</footer></main></div>${w.hostKey?`<dialog open aria-labelledby="host-title"><h2 id="host-title">${w.hostKey.Kind==='first-use'?'Первое подключение SSH':'Ключ SSH изменился'}</h2><p>Сравните отпечаток с известным ключом роутера через доверенный канал.</p><dl><dt>Адрес</dt><dd>${escape(w.hostKey.Address)}</dd><dt>Алгоритм</dt><dd>${escape(w.hostKey.Algorithm)}</dd></dl><code class="fingerprint">${escape(w.hostKey.Fingerprint)}</code>${w.hostKey.Expected?`<p>Ожидался: <code>${escape(w.hostKey.Expected)}</code></p>`:''}<div class="actions">${w.hostKey.Kind==='first-use'?'<button data-action="confirm-host">Отпечаток совпадает, подключиться</button>':'<p class="error">Автоматическая замена заблокирована.</p>'}<button class="secondary" data-action="reject-host">Отмена</button></div></dialog>`:''}${w.trust?`<dialog open aria-labelledby="trust-title"><h2 id="trust-title">Доверие сертификату CA</h2><p>${escape(w.trust.Description||w.trust.Manual)}</p><p>Это отдельное изменение системного хранилища доверия на этом компьютере.</p><div class="actions">${w.trust.ID?'<button data-action="apply-trust">Разрешаю установку этого CA</button>':''}<button class="secondary" data-action="reject-trust">Не устанавливать</button></div></dialog>`:''}`;
  if(w.step===6&&w.plan?.Files?.length){
   const previews=document.createElement('div');previews.className='file-previews';
   const heading=document.createElement('h2');heading.textContent='Файлы конфигурации';previews.append(heading);
   const note=document.createElement('p');note.textContent='Содержимое конфигураций скрыто; доступны пути, действия и обезличенный предпросмотр.';previews.append(note);
   for(const file of w.plan.Files){
    const details=document.createElement('details');details.open=true;
    const summary=document.createElement('summary');
    const action=({create:'Создать',preserve:'Сохранить без изменения'} as Record<string,string>)[file.Action]??file.Action;
    summary.textContent=`${file.Path}: ${action}`;
    const preview=document.createElement('pre');preview.textContent=file.Preview;
    details.append(summary,preview);previews.append(details);
   }
   root.querySelector('.changes')?.after(previews);
  }
  if(w.step===8){
   const back=root.querySelector<HTMLButtonElement>('[data-action="back"]');if(back)back.disabled=true;
   if(w.result?.Completed?.length||w.result?.Applied?.length){
    const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Завершённые этапы и записанные файлы';details.append(summary);
    const list=document.createElement('ul');for(const item of [...(w.result.Completed??[]),...(w.result.Applied??[])]){const li=document.createElement('li');li.textContent=stageTitle(item);list.append(li);}details.append(list);root.querySelector('section')?.append(details);
   }
  }
  if(w.busy||w.running)root.querySelectorAll<HTMLInputElement|HTMLSelectElement>('input,select').forEach(el=>el.disabled=true);
 }
 root.addEventListener('input',event=>{
  const input=event.target as HTMLInputElement;const id=input.id;
  if(['host','port','user','password'].includes(id)){if(id==='port')w.connection.Port=Number(input.value);else w.connection[({host:'Host',user:'User',password:'Password'} as const)[id as 'host'|'user'|'password']]=input.value;w.connectionChanged();}
  if(id==='provider'){w.selection.ProviderURL=input.value;w.selection.ImportText='';w.selectionChanged();}
 });
 root.addEventListener('change',async event=>{
  const el=event.target as HTMLInputElement;
  if(el.id==='prepared')w.prepared=el.checked;
  if(el.id==='reviewed')w.reviewed=el.checked;
  if(el.name==='cores'){w.selection.Cores=el.value==='both'?['mihomo','xray']:[el.value];if(!w.selection.Cores.includes(w.selection.ActiveCore))w.selection.ActiveCore=w.selection.Cores[0];w.selection.ImportCore=w.selection.ActiveCore;w.selectionChanged();}
  if(el.id==='active'){w.selection.ActiveCore=el.value;w.selectionChanged();}
  if(w.selection.ActiveCore!=='mihomo')w.selection.Watchdog=false;
  if(el.id==='ui'){w.selection.UI=el.checked;w.selectionChanged();}
  if(el.id==='watchdog'){w.selection.Watchdog=el.checked;w.selectionChanged();}
  if(el.id==='import-core'){w.selection.ImportCore=el.value;w.selectionChanged();}
  if(el.id==='import-file'){const file=el.files?.[0];if(file){if(file.size>2*1024*1024)w.message='Размер файла превышает 2 МиБ';else{w.selection.ImportText=await file.text();w.selection.ProviderURL='';w.selectionChanged();}}}
  render();
 });
 root.addEventListener('click',async event=>{
  const button=(event.target as HTMLElement).closest<HTMLButtonElement>('button[data-action]');if(!button||button.disabled)return;
  try{switch(button.dataset.action){
   case 'next':w.next();break;case 'back':w.step=Math.max(0,w.step-1);w.reviewed=false;break;
   case 'inspect':{const task=w.inspect();render();await task;break;}
   case 'prepare':{const task=w.prepare();render();await task;break;}
   case 'start':{const task=w.start();render();await task;break;}
   case 'cancel':await w.cancel();break;
   case 'confirm-host':await w.confirmHost();break;
   case 'reject-host':w.hostKey=null;w.connection.Password='';break;
   case 'verify':button.disabled=true;w.result=await w.backend.Verify();break;
   case 'trust':w.trust=await w.backend.PrepareTrust();break;
   case 'reject-trust':w.trust=null;break;
   case 'apply-trust':if(w.trust?.ID){button.disabled=true;const result=await w.backend.ApplyTrust(w.trust.ID,true);w.message=result.Detail;w.trust=null;}break;
   case 'export':exported=await w.backend.ExportRedactedReport();break;
   case 'end':exported='';await w.end();break;
  }}catch{w.message='Операция не завершена. Повторите проверку состояния.';}
  render();
 });
 render();return render;
}
