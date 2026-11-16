import {Wizard,type Check} from './wizard';
import {Quit} from '../wailsjs/runtime/runtime';
const steps=['Подготовка','Подключение','Проверка роутера','Ядра','Компоненты','Конфигурация','План изменений','Установка','Результат'];
const escape=(value:unknown)=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const field=(id:string,label:string,value:string|number,type='text')=>`<label for="${id}">${label}<input id="${id}" type="${type}" value="${escape(value)}" autocomplete="off"></label>`;
const states:Record<string,string>={passed:'Подтверждено',failed:'Не подтверждено',pending:'Ожидает проверки','not-applicable':'Не требуется',unconfigured:'Нужна настройка','matched-reviewed-plan':'Соответствует плану'};
const stageTitle=(id:string)=>({cron:'Запуск и проверка планировщика',subscriptions:'Настройка обновления подписок',download:'Загрузка и проверка артефактов',reinspect:'Повторная проверка роутера',backup:'Резервная копия',dependencies:'Установка зависимостей',stop:'Остановка служб',install:'Установка компонентов',configure:'Сохранение конфигураций',validate:'Проверка конфигураций',activate:'Запуск активного ядра',watchdog:'Настройка watchdog',tls:'Проверка TLS',ui:'Запуск панели',preservation:'Проверка сохранности настроек',transfer:'Передача и обратная проверка архива',trigger:'Запуск обработки OPKG','waiting-shell':'Ожидание SSH Entware',finished:'Завершение'} as Record<string,string>)[id]??id;
const check=(c:Check)=>`<span class="state ${escape(c.State)}">${escape(states[c.State]??c.State)}</span><small>${escape(c.Detail)}</small>`;

export function mount(root:HTMLElement,w:Wizard){
 let exported='';let passwordVisible=false;
 function progressScreen():string {
  const steps=w.mode==='existing'?w.plan?.Steps??[]:[];
  const planned=steps.filter((step,index)=>steps.findIndex(candidate=>candidate.ID===step.ID)===index);
  const completed=new Set(w.progress.filter(stage=>stage.Status==='completed').map(stage=>stage.Step));
  const count=planned.filter(step=>completed.has(step.ID)).length;
  const summary=planned.length?`<label for="install-progress">Выполнено этапов ${count} из ${planned.length}</label><progress id="install-progress" value="${count}" max="${planned.length}"></progress>`:`<p>Завершено этапов: ${completed.size}</p>`;
  const statuses:Record<string,string>={running:'Выполняется',completed:'Завершено',failed:'Ошибка',cancelled:'Отменено',pending:'Ожидает'};
  return `<div class="installation-progress" aria-live="polite">${summary}<ol class="progress">${w.progress.map(stage=>{
   const description=planned.find(step=>step.ID===stage.Step)?.Description;
   const title=stageTitle(stage.Step);
   return `<li><div class="progress-heading"><strong>${escape(title===stage.Step?description||'Этап установки':title)}</strong> <span>${escape(statuses[stage.Status]??'Ожидает')}</span></div>${description&&description!==title?`<small>${escape(description)}</small>`:''}</li>`;
  }).join('')}</ol></div>`;
 }
 function bootstrapScreen():string {
  if(w.bootstrapWaiting)return `<p class="lead">Требуется проверка SSH Entware</p><p>Копирование архива и команда OPKG не подтверждают работоспособность Entware. Проверьте Initrc в KeeneticOS и дождитесь завершения обработки.</p><button data-action="connect-shell">Подключиться к SSH Entware</button>`;
  const s=w.bootstrap,p=w.bootstrapPlan;if(!s)return '<p>Повторите подключение к KeeneticOS.</p>';
  if(w.running)return `<p>Выполняется подтверждённый план Entware</p>${progressScreen()}<button data-action="cancel">Остановить дальнейшие этапы</button>`;
  return `<dl><dt>Модель</dt><dd>${escape(s.Model)} (${escape(s.Hardware)})</dd><dt>Архитектура</dt><dd>${escape(s.Arch)}</dd></dl><label>Целевой EXT4-раздел<select id="bootstrap-volume"><option value="">Выберите раздел</option>${s.Volumes.map(v=>`<option value="${escape(v.UUID)}" ${v.UUID===w.bootstrapUUID?'selected':''}>${escape(v.Label)} — ${escape(v.UUID)} — ${(v.Free/1048576).toFixed(0)} МиБ свободно${v.Share?'':' — нет корневого SMB-ресурса'}</option>`).join('')}</select></label><button data-action="prepare-bootstrap" ${!w.bootstrapUUID||w.busy?'disabled':''}>Подготовить план Entware</button>${p?`<h2>План установки Entware</h2><p>Раздел: <code>${escape(p.Volume.UUID)}</code>, SMB: ${escape(p.Volume.Share)}</p><p>Архив: <code>install/${escape(p.Archive)}</code> (${p.Size} байт)</p><p>Источник: ${escape(p.URL)}</p><p>SHA256: <code>${escape(p.SHA256)}</code></p><p>Хеш закреплён разработчиком установщика для проверенных байтов; опубликованным checksum Entware он не является.</p><p>После проверки архива и обратного чтения будут выполнены команды:</p><pre>${escape(p.Commands.join('\n'))}</pre><p>Если диск уже выбран в OPKG, план явно отключает его привязку и повторно назначает тот же UUID. Другой OPKG-диск и существующие файлы Entware блокируют установку. На проверенном пустом разделе мастер временно задаст Initrc /opt/etc/init.d, чтобы KeeneticOS запустил doinstall из архива. Установщик из локального набора затем задаёт /opt/etc/init.d/rc.unslung. Пользовательский initrc блокирует установку. Перед продолжением мастер проверит конечный путь и исполняемый файл.</p><label class="check"><input id="bootstrap-reviewed" type="checkbox" ${w.bootstrapReviewed?'checked':''}>Разрешаю передачу этого архива и перечисленные изменения OPKG на этом разделе</label><button data-action="start-bootstrap" ${!w.bootstrapReviewed||w.busy?'disabled':''}>Установить Entware по этому плану</button>`:''}`;
 }
 function screen():string {
  switch(w.step){
  case 0:return `<p class="lead">Установка Xkeen и панели управления с сохранением настроек роутера</p>
   <h2>Подготовьте Keenetic</h2>
   <p>Подключите компьютер к домашней сети роутера и откройте его веб-панель: обычно <code>http://192.168.1.1</code>. Если адрес меняли, используйте свой. Названия ниже относятся к русскому интерфейсу; в разных версиях KeeneticOS «Общие настройки» могут называться «Параметры системы».</p>
   <aside>Если Entware уже работает, пропустите форматирование и повторную установку Entware. Сохраните существующий накопитель, init-скрипт и настройки. Форматирование удаляет данные; мастер его не выполняет.</aside>
   <details open><summary>1. Установите компоненты KeeneticOS</summary>
    <ol class="preparation">
     <li>Откройте <strong>Управление → Общие настройки (Параметры системы) → Обновления и компоненты → Изменить набор компонентов</strong>.</li>
     <li>В группе <strong>Пакеты OPKG</strong> отметьте <strong>Поддержка открытых пакетов</strong> и <strong>Модули ядра подсистемы Netfilter</strong>. Для USB-накопителя нужны <strong>Интерфейс USB</strong> и <strong>Файловая система Ext</strong> — проверьте, что они установлены. Названия и доступность зависят от модели.</li>
     <li>Установите <strong>Сервер SSH</strong>. Для приведённого ниже варианта DNS добавьте <strong>Прокси-сервер DNS-over-HTTPS</strong>; для DNS-over-TLS вместо него нужен соответствующий компонент DoT.</li>
     <li>Для автоматической установки Entware установите <strong>Общий доступ к файлам и принтерам по протоколу SMB</strong> и разрешите доступ к корню нужного раздела. В KeeneticOS 5.1+ для форматирования на роутере установите также утилиты файловой системы EXT4.</li>
     <li>Нажмите кнопку установки/обновления компонентов и дождитесь завершения и возможной перезагрузки. Снова войдите в веб-панель. Не удаляйте уже используемые компоненты.</li>
    </ol>
   </details>
   <details><summary>2. Подготовьте новый накопитель: EXT4</summary>
    <p>Этот раздел нужен только для нового или пустого накопителя. Сначала скопируйте с него нужные файлы. Для Entware используйте раздел <strong>EXT4</strong> с меткой, например <code>ENTWARE</code>; FAT32, exFAT и NTFS для этого раздела не подходят.</p>
    <ol class="preparation">
     <li><strong>На роутере с KeeneticOS 5.1+:</strong> подключите накопитель, откройте <strong>Управление → Накопители и устройства</strong>, найдите его по размеру и модели. Для нужного раздела нажмите <strong>Форматировать</strong>, выберите <strong>EXT4</strong>, задайте метку, если поле доступно, и подтвердите. Не выбирайте другой диск. Кнопка <strong>Инициализировать</strong> стирает уже весь накопитель — для форматирования одного раздела она не нужна.</li>
     <li><strong>Windows:</strong> используйте <strong>DiskGenius</strong> с официального сайта diskgenius.com. Выберите именно USB-раздел по размеру → <strong>Format Current Partition</strong> → файловая система <strong>EXT4</strong> → метка <code>ENTWARE</code> → <strong>Format</strong>. Обычные «Проводник» и «Управление дисками» EXT4 не создают.</li>
     <li><strong>Linux:</strong> в <strong>GParted</strong> (gparted.org) выберите USB-устройство справа сверху → размонтируйте его раздел → <strong>Раздел → Форматировать в → ext4</strong> → примените операции. Для пустого неразмеченного диска сначала создайте раздел EXT4 через <strong>Раздел → Новый</strong>; задайте метку <code>ENTWARE</code>.</li>
     <li><strong>macOS:</strong> используйте форматирование на роутере из первого пункта либо GParted в Linux, запущенном на компьютере или в виртуальной машине с передачей USB-накопителя. Штатная «Дисковая утилита» EXT4 не создаёт. Не заменяйте его APFS или exFAT.</li>
     <li>Безопасно извлеките накопитель из компьютера, подключите к Keenetic и убедитесь, что раздел виден в <strong>Управление → Накопители и устройства</strong> (на старых версиях — в разделе USB-устройств на странице <strong>Приложения</strong>).</li>
    </ol>
   </details>
   <details><summary>3. Подключите мастер для установки Entware</summary>
    <p>Для новой установки нужны SSH KeeneticOS и SMB-компонент. Разрешите своей учётной записи доступ к существующему SMB-ресурсу, который открывает <strong>корень EXT4-раздела</strong>. Ресурс отдельной папки не подходит. Мастер не создаёт общие ресурсы и не включает службы.</p>
    <p>На следующем шаге выберите «Новая установка Entware», укажите SSH администратора KeeneticOS (обычно <code>admin</code>, порт <code>22</code>). Мастер определит модель и архитектуру, предложит EXT4-раздел и покажет конкретный план. После подтверждения он скачает, проверит и перенесёт архив, временно задаст Initrc /opt/etc/init.d для запуска установщика и запустит OPKG. Штатный установщик задаст конечный /opt/etc/init.d/rc.unslung. Искать, выбирать и копировать архив вручную не нужно.</p>
    <p>После обработки OPKG проверьте в веб-панели KeeneticOS поле <strong>Initrc</strong>: <code>/opt/etc/init.d/rc.unslung</code>. Существующий пользовательский init-скрипт не заменяйте. Затем проверьте через мастер <strong>SSH Entware</strong>: обычно <code>root</code>, порт <code>222</code>. Используйте текущий пароль; начальный пароль новой установки смените командой <code>passwd</code> в shell Entware.</p>
    <p>Если Entware уже работает, сразу выберите существующую установку и SSH Entware. Повторная установка на накопитель с Entware блокируется.</p>
   </details>
   <details><summary>4. Настройте DNS для новой установки</summary>
    <p>Базовый вариант: клиенты обращаются за DNS к роутеру, а роутер использует доступный DoH-сервер. Шифрование DNS не означает автоматического проксирования всего трафика.</p>
    <ol class="preparation">
     <li>Откройте <strong>Сетевые правила → Интернет-фильтр → Настройка DNS</strong>. В <strong>Профили DNS</strong> нажмите <strong>Добавить сервер</strong>.</li>
     <li>Выберите тип <strong>DNS-over-HTTPS</strong>, адрес, например <code>https://cloudflare-dns.com/dns-query</code>, и <strong>Любой интерфейс</strong> либо ваш рабочий интернет-канал. Сохраните. Это пример, а не обязательный провайдер: используйте доступный в вашей сети DoH/DoT. Если интерфейс просит bootstrap-IP для этого примера, адреса Cloudflare — <code>1.1.1.1</code> и <code>1.0.0.1</code>.</li>
     <li>Для выбранных клиентов используйте профиль <strong>Без фильтрации</strong>, если хотите, чтобы они использовали настроенный DoH/DoT, а не DNS другого интернет-фильтра. Не включайте «Игнорировать DNS провайдера» только ради XKeen: для этой базовой схемы отдельное изменение WAN не требуется.</li>
     <li>Для простой схемы с одним DNS-профилем на этой же странице отключите <strong>Разрешить транзит DNS-запросов</strong>: обычные DNS-запросы клиентов будут обрабатываться роутером. Если у вас уже настроены NextDNS, AdGuard Home или несколько DNS-профилей, сначала согласуйте их схему: запрет транзита может нарушить работу. Существующие настройки вслепую не заменяйте.</li>
     <li>В настройках сети клиентов оставьте получение DNS по DHCP/автоматически, то есть DNS-адрес роутера. Собственный Secure DNS/DoH в браузере или Private DNS на устройстве обходит этот путь. При проверке этой схемы используйте DNS роутера. Убедитесь, что сайты открываются ещё до установки XKeen.</li>
    </ol>
   </details>
   <details><summary>5. Создайте политику xkeen и назначьте клиентов</summary>
    <p>Политика выбирает устройства, чей трафик будет обрабатывать XKeen; правила самого Mihomo/Xray затем определяют, что идёт через прокси. Для первого запуска достаточно политики <code>xkeen</code>, без отдельного VPN- или SOCKS-подключения.</p>
    <ol class="preparation">
     <li>В <strong>Мои сети и Wi-Fi → Списки клиентов</strong> откройте нужное устройство и зарегистрируйте его, если оно ещё не зарегистрировано. Проверьте имя и MAC-адрес; случайный MAC телефона должен оставаться стабильным для этой Wi-Fi-сети.</li>
     <li>Перейдите в <strong>Интернет → Приоритеты подключений → Политики доступа в интернет</strong>. Нажмите <strong>Добавить политику</strong>, укажите имя <code>xkeen</code> латиницей и сохраните. Для существующего XKeen сохраняйте уже согласованное имя политики.</li>
     <li>В созданной политике отметьте <strong>ваше действующее подключение к провайдеру</strong> и сохраните. Не оставляйте список подключений пустым — у клиентов этой политики должен быть выход в интернет.</li>
     <li>Откройте соседнюю вкладку <strong>Применение политик</strong>. В «Политике по умолчанию» выберите зарегистрированное устройство → <strong>Переместить в → xkeen → Подтвердить</strong>; в версиях с перетаскиванием можно перенести устройство на политику <code>xkeen</code>. Повторите для остальных нужных клиентов.</li>
     <li>Остальные устройства оставьте в своей текущей политике. Проверьте интернет у выбранного клиента до установки. Без политики XKeen может применяться ко всем клиентам; отсутствие политики не следует считать способом отключить прокси. Если ядро ещё не настроено, не считайте назначение политики гарантией доступа через прокси.</li>
    </ol>
   </details>
   <details><summary>6. Порт управления и RCI-токен: когда нужны и как настроить</summary>
    <h3>HTTPS-порт роутера: для TProxy</h3>
    <p>Для режима <strong>TProxy</strong> или отдельного force-TProxy inbound для DSCP 61 нужно освободить HTTPS-порт <code>443</code> веб-панели Keenetic. Обычному <strong>Hybrid</strong> это не требуется. HTTPS-панель XKeen UI использует другой порт — по умолчанию <code>1000</code>.</p>
    <ol class="preparation">
     <li>Если вашей схеме нужен свободный 443, откройте <strong>Управление → Пользователи и доступ → Службы управления</strong>.</li>
     <li>В поле <strong>Порт HTTPS</strong> выберите свободный, например <code>8443</code>, и сохраните. Не путайте его с SSH-портом или портом XKeen UI.</li>
     <li>Проверьте новый адрес веб-панели: <code>https://192.168.1.1:8443</code> (со своим IP). HTTP-порт и доступ из интернета для этого менять не требуется.</li>
    </ol>
    <h3>RCI-токен: для KeeneticOS 5.2 и новее</h3>
    <p>RCI — API роутера. Через него XKeen получает сведения о политиках и системе; UI также использует его для функций работы с роутером. Это отдельный секрет, а не SSH-пароль. На версиях до 5.2 этот этап обычно не нужен.</p>
    <ol class="preparation">
     <li>В <strong>Управление → Пользователи и доступ</strong> найдите раздел токенов доступа. Добавьте токен для XKeen и скопируйте показанное значение в закрытый локальный файл. Не отправляйте его в чат или журнал.</li>
     <li>Сохраните токен в <code>/opt/etc/xkeen/xkeen.json</code> в поле <code>xkeen.rci_token</code>. Для нового файла структура приведена ниже. Если файл уже существует, измените только это поле, сохранив остальные настройки.</li>
    </ol>
    <pre>{
  "xkeen": {
    "rci_token": "ВСТАВЬТЕ_СВОЙ_ТОКЕН"
  }
}</pre>
    <p>Файл можно подготовить в локальном текстовом редакторе и загрузить через файловый браузер веб-панели в <code>etc/xkeen/xkeen.json</code> выбранного накопителя Entware: его корень на роутере смонтирован как <code>/opt</code>. При необходимости создайте каталоги <code>etc/xkeen</code>. Существующий файл сначала скачайте для редактирования, не заменяйте его минимальным примером. Либо отредактируйте файл в shell Entware. После загрузки выполните там <code>chmod 600 /opt/etc/xkeen/xkeen.json</code>. Мастер не выпускает и не отзывает RCI-токены.</p>
   </details>
   <aside>Все действия в веб-панели выполняете вы. Мастер не форматирует диск и не перезагружает роутер. Для нового Entware он изменит только выбранный OPKG-диск по подтверждённому плану; для существующей установки сохраните её рабочую схему.</aside>
   <label class="check"><input id="prepared" type="checkbox" ${w.prepared?'checked':''}>Подготовка выполнена, накопитель подключён</label>`;
  case 1:return `<label>Режим подключения<select id="connection-mode"><option value="existing" ${w.mode==='existing'?'selected':''}>Существующий Entware</option><option value="new" ${w.mode==='new'?'selected':''}>Новая установка Entware через KeeneticOS</option></select></label><p>Используйте адрес роутера в вашей сети. Пароль нужен только для текущего SSH-подключения.</p><div class="form-grid">${field('host','Адрес роутера',w.connection.Host)}${field('port','SSH-порт',w.connection.Port,'number')}${field('user','Имя пользователя',w.connection.User)}<label for='password'>Пароль SSH<div class='password-input'><input id='password' type='${passwordVisible?"text":"password"}' value='${escape(w.connection.Password)}' autocomplete='off' spellcheck='false'><button type='button' class='secondary' data-action='toggle-password' aria-controls='password' aria-label='${passwordVisible?"Скрыть пароль":"Показать пароль"}' aria-pressed='${passwordVisible}'>${passwordVisible?"Скрыть":"Показать"}</button></div></label></div><p class='muted'>${w.mode==='new'?'Для новой установки нужен SSH администратора KeeneticOS (обычно admin, порт 22) и доступ SMB той же учётной записью к корню EXT4.':'Для существующей установки нужен SSH Entware: обычно root, порт 222. Если порт меняли, укажите свой.'}</p><aside>Перед первым подключением отдельно сравните отпечаток ключа SSH. Неожиданная замена известного ключа блокируется. Подтверждённый ключ хранится только до закрытия приложения.</aside><button data-action="inspect" ${w.busy?'disabled':''}>Проверить роутер</button>`;
  case 2:{if(w.mode==='new')return bootstrapScreen();const s=w.inspection;return s?`<p class="lead">${s.Entware?'Entware обнаружен':'Entware не установлен'}</p><dl><dt>Архитектура</dt><dd>${escape(s.Arch)}</dd><dt>Свободное место</dt><dd>${(s.Available/1048576).toFixed(0)} МиБ</dd><dt>Активное ядро</dt><dd>${escape(s.ActiveCore)}</dd></dl><h2>Обнаруженные версии</h2><ul>${Object.entries(s.Versions).map(([name,version])=>`<li>${escape(name)} <strong>${escape(version)}</strong></li>`).join('')}</ul>${!s.Entware?'<aside>Вернитесь к подключению и выберите новую установку Entware. Готовность подтверждается успешной проверкой SSH Entware.</aside>':''}<p class="muted">Проверка актуальна 5 минут. Перед записью backend снова сравнит фактическое состояние.</p>`:'<p>Повторите подключение и проверку.</p>';}
  case 3:return `<p>Выберите ядра. При двух ядрах запускается только выбранное активное ядро.</p><div class="choices">${[['mihomo','Mihomo','YAML, подписки и группы Clash'],['xray','Xray','JSON, соединения и маршрутизация Xray'],['both','Mihomo и Xray','Оба установлены, одно активно']].map(([value,title,desc])=>`<label><input type="radio" name="cores" value="${value}" ${(value==='both'?w.selection.Cores.length===2:w.selection.Cores.length===1&&w.selection.Cores[0]===value)?'checked':''}><span><strong>${title}</strong><small>${desc}</small></span></label>`).join('')}</div><label>Активное ядро<select id="active">${w.selection.Cores.map(c=>`<option ${c===w.selection.ActiveCore?'selected':''}>${c}</option>`).join('')}</select></label><aside>Существующее активное ядро сохраняется по умолчанию. Переключение требует согласованного плана. Для запуска нового Xray укажите JSON-подписки или импортируйте полностью настроенный JSON.</aside>`;
  case 4:return `<label class="check"><input id="ui" type="checkbox" ${w.selection.UI?'checked':''}>XKeen UI PWA: панель по HTTPS</label><p>Существующие данные панели и корректные сертификаты сохраняются. Новый CA остаётся в закрытом хранилище на компьютере.</p><label class="check"><input id="watchdog" type="checkbox" ${w.selection.Watchdog?'checked':''} ${w.selection.ActiveCore!=='mihomo'?'disabled':''}>router-watchdog: автоматическая проверка узлов Mihomo</label><p>Watchdog работает только с активным совместимым Mihomo: нужны provider-backed группы Proxy/BENCHMARK (или прежнюю PROXY), API secret, HTTP listener и проверенный cron. Для активного Xray он недоступен.</p>`;
  case 5:return `<p>Существующие конфигурации сохраняются без перезаписи. Для новой установки выберите локальный файл или до 10 HTTPS-подписок отдельно для каждого выбранного ядра. Xray принимает JSON-объект с outbounds или массив таких объектов; импортируются только прокси-подключения, базовые DNS и маршруты сохраняются.</p><label>Ядро для импорта<select id="import-core">${w.selection.Cores.map(c=>`<option ${c===w.selection.ImportCore?'selected':''}>${c}</option>`).join('')}</select></label><label>Локальный YAML / JSON (до 2 МиБ)<input id="import-file" type="file" accept=".yaml,.yml,.json"></label><p class="muted">${w.selection.ImportText?'Локальная конфигурация прочитана; содержимое не включается в журнал.':'Файл не выбран. Существующие настройки будут использованы автоматически.'}</p>${w.selection.Cores.map(core=>{const values=core==='mihomo'?w.selection.MihomoProviderURLs:w.selection.XrayProviderURLs;const rows=values.length?values:[''];return `<fieldset><legend>Подписки ${core==='mihomo'?'Mihomo':'Xray'} (HTTPS, до 10)</legend>${rows.map((value,index)=>`<label for="provider-${core}-${index}">Подписка ${index+1}<input id="provider-${core}-${index}" data-provider="${core}" data-index="${index}" type="password" value="${escape(value)}" autocomplete="off" spellcheck="false"></label><button type="button" class="secondary" data-action="remove-provider" data-core="${core}" data-index="${index}" ${w.busy||w.running?'disabled':''}>Удалить подписку ${index+1}</button>`).join('')}<button type="button" class="secondary" data-action="add-provider" data-core="${core}" ${rows.length>=10||w.busy||w.running?'disabled':''}>+ Добавить подписку ${core==='mihomo'?'Mihomo':'Xray'}</button></fieldset>`;}).join('')}<p class="muted">URL подписок считаются секретами. Они скрыты в полях, не сохраняются в browser storage и не выводятся в отчёт. На роутере адреса хранятся в закрытых файлах конфигурации. Локальный файл и подписки используются по отдельности: новый ввод очищает предыдущий вариант.</p><button data-action="prepare" ${w.busy?'disabled':''}>Подготовить план</button>`;
  case 6:{const p=w.plan;return p?`${p.Message?`<aside class="warning">${escape(p.Message)}</aside>`:''}${p.Conflicts?.length?`<h2>Требует согласования</h2><p>Неоднозначное слияние блокирует установку. Согласуйте конфигурацию вручную и повторите проверку.</p>${p.Conflicts.map(c=>`<details><summary>${escape(c.Path||'Конфигурация')}</summary><p>${escape(c.Reason)}</p>${c.NecessaryAddition?`<pre>${escape(c.NecessaryAddition)}</pre>`:''}</details>`).join('')}`:''}<h2>Версии и изменения</h2><p>${(p.Artifacts??[]).map(a=>`${escape(a.Component)} ${escape(a.Version)}`).join(', ')||'Готовый план пока отсутствует'}</p><ul class="changes">${(p.Changes??[]).map(c=>`<li><code>${escape(c.Path)}</code><span>${escape(c.Action)}</span><small>Права: ${escape(c.Mode)}</small></li>`).join('')}</ul><details><summary>Последовательность и зависимости</summary><ol>${(p.Steps??[]).map(s=>`<li>${escape(s.Description)}</li>`).join('')}</ol><p>${escape((p.Dependencies??[]).join(', '))}</p></details><p>Закрытая резервная копия создаётся и проверяется до изменения пакетов и служб. При ошибке копирования или нехватке места установка останавливается.</p>${(p.Notes??[]).map(n=>`<p class="muted">${escape(n)}</p>`).join('')}<label class="check"><input id="reviewed" type="checkbox" ${w.reviewed?'checked':''} ${!p.ID?'disabled':''}>Я просмотрел конкретный план и разрешаю перечисленные изменения на роутере</label><button data-action="start" ${!p.ID||!w.reviewed||w.busy?'disabled':''}>Установить по этому плану</button>`:'<p>Вернитесь к конфигурации и подготовьте план.</p>';}
  case 7:return `<p class="lead">Выполняется подтверждённый план</p><p>Не отключайте роутер и накопитель. Отмена останавливает дальнейшие этапы, но не откатывает завершённые записи.</p>${progressScreen()}<button class="secondary" data-action="cancel">Остановить дальнейшие этапы</button>`;
  case 8:{const r=w.result;return `<p class="lead">${escape(r?.Message)}</p>${w.completionBusy?'<p role="status">Настраиваем доверие CA. Если система запросит разрешение на установку сертификата, подтвердите его.</p>':''}${r?.Backup?`<p>Резервная копия: <code>${escape(r.Backup)}</code></p>`:''}${r?.Uncertain?`<aside>Неподтверждённый этап: ${escape(r.Uncertain)}. Повторите проверку состояния.</aside>`:''}<ul>${(r?.Pending??[]).map(p=>`<li>${escape(p)}</li>`).join('')}</ul>${r?.Status==='installed'?'<div class="actions"><button data-action="verify">Проверить службы и HTTPS</button><button class="secondary" data-action="trust">Повторить настройку доверия CA</button></div>':''}${r?.PanelURL?`<p>Панель: <code>${escape(r.PanelURL)}</code></p>`:''}${r?.Services?.length?`<div class="table-wrap"><table><thead><tr><th>Служба</th><th>Процесс</th><th>Настройки</th><th>API</th><th>HTTPS</th><th>Доверие</th></tr></thead><tbody>${r.Services.map(s=>`<tr><th>${escape(s.Component)}</th>${[s.Process,s.Configuration,s.API,s.HTTPS,s.Trust].map(c=>`<td>${check(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:''}<p>Системное доверие CA подтверждается отдельно. На других устройствах установите только публичный сертификат CA вручную.</p><button class="secondary" data-action="export">Показать обезличенный отчёт</button>${exported?`<label>Отчёт для копирования<textarea readonly rows="12">${escape(exported)}</textarea></label>`:''}<button data-action="finish">Завершить</button>`;}
  default:return '';
  }
 }
 function render(){
  if(w.step!==1||w.busy)passwordVisible=false;
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
  if(w.completionBusy)root.querySelectorAll<HTMLInputElement|HTMLSelectElement|HTMLButtonElement>('input,select,button').forEach(el=>el.disabled=true);
 }
 root.addEventListener('input',event=>{
  const input=event.target as HTMLInputElement;const id=input.id;
  if(['host','port','user','password'].includes(id)){if(id==='port')w.connection.Port=Number(input.value);else w.connection[({host:'Host',user:'User',password:'Password'} as const)[id as 'host'|'user'|'password']]=input.value;w.connectionChanged();}
  if(input.dataset.provider){const key=input.dataset.provider==='mihomo'?'MihomoProviderURLs':'XrayProviderURLs';w.selection[key][Number(input.dataset.index)]=input.value;w.selection.ImportText='';w.selectionChanged();}
 });
 root.addEventListener('change',async event=>{
  const el=event.target as HTMLInputElement;
  // Text fields update on input. Replacing them on blur detaches the button
  // between pointerdown and click, swallowing the user's first action.
  if(['host','port','user','password'].includes(el.id)||el.dataset.provider)return;
  if(el.id==='connection-mode'){w.setMode(el.value==='new'?'new':'existing');}
  if(el.id==='bootstrap-volume'){w.bootstrapUUID=el.value;w.bootstrapPlan=null;w.bootstrapReviewed=false;}
  if(el.id==='bootstrap-reviewed')w.bootstrapReviewed=el.checked;
  if(el.id==='prepared')w.prepared=el.checked;
  if(el.id==='reviewed')w.reviewed=el.checked;
  if(el.name==='cores'){w.selection.Cores=el.value==='both'?['mihomo','xray']:[el.value];if(!w.selection.Cores.includes(w.selection.ActiveCore))w.selection.ActiveCore=w.selection.Cores[0];w.selection.ImportCore=w.selection.ActiveCore;w.selectionChanged();}
  if(el.id==='active'){w.selection.ActiveCore=el.value;w.selectionChanged();}
  if(w.selection.ActiveCore!=='mihomo')w.selection.Watchdog=false;
  if(el.id==='ui'){w.selection.UI=el.checked;w.selectionChanged();}
  if(el.id==='watchdog'){w.selection.Watchdog=el.checked;w.selectionChanged();}
  if(el.id==='import-core'){w.selection.ImportCore=el.value;w.selectionChanged();}
  if(el.id==='import-file'){const file=el.files?.[0];if(file){if(file.size>2*1024*1024)w.message='Размер файла превышает 2 МиБ';else{w.selection.ImportText=await file.text();w.clearSubscriptions();w.selectionChanged();}}}
  render();
 });
 root.addEventListener('click',async event=>{
  const button=(event.target as HTMLElement).closest<HTMLButtonElement>('button[data-action]');if(!button||button.disabled)return;
  if(button.dataset.action==='toggle-password'){
   const input=root.querySelector<HTMLInputElement>('#password');if(!input||w.busy)return;
   const start=input.selectionStart,end=input.selectionEnd;passwordVisible=!passwordVisible;input.type=passwordVisible?'text':'password';
   button.textContent=passwordVisible?'Скрыть':'Показать';button.setAttribute('aria-label',passwordVisible?'Скрыть пароль':'Показать пароль');button.setAttribute('aria-pressed',String(passwordVisible));
   input.focus();if(start!==null&&end!==null)input.setSelectionRange(start,end);return;
  }
  try{switch(button.dataset.action){
   case 'add-provider':case 'remove-provider':{if(w.busy||w.running)break;const core=button.dataset.core;if(core!=='mihomo'&&core!=='xray')break;const key=core==='mihomo'?'MihomoProviderURLs':'XrayProviderURLs';let values=w.selection[key];if(button.dataset.action==='add-provider'){if(!values.length)values=[''];if(values.length>=10)break;values.push('');}else{values.splice(Number(button.dataset.index),1);}w.selection[key]=values;w.selection.ImportText='';w.selectionChanged();break;}
   case 'next':w.next();break;case 'back':w.step=Math.max(0,w.step-1);w.reviewed=false;break;
   case 'prepare-bootstrap':{const task=w.prepareBootstrap();render();await task;break;}
   case 'start-bootstrap':{const task=w.startBootstrap();render();await task;break;}
   case 'connect-shell':w.connectShell();break;
   case 'retry-bootstrap':w.setMode('new');w.step=1;break;
   case 'inspect':{const task=w.inspect();render();await task;break;}
   case 'prepare':{const task=w.prepare();render();await task;break;}
   case 'start':{const task=w.start();render();await task;break;}
   case 'cancel':await w.cancel();break;
   case 'confirm-host':await w.confirmHost();break;
   case 'reject-host':w.hostKey=null;w.connection.Password='';break;
   case 'verify':{const task=w.verifyInstalled();render();await task;break;}
   case 'trust':{const task=w.prepareTrust();render();await task;break;}
   case 'reject-trust':w.rejectTrust();break;
   case 'apply-trust':{const task=w.applyTrust();render();await task;break;}
   case 'export':exported=await w.backend.ExportRedactedReport();break;
   case 'finish':w.clearSensitiveInputs();Quit();break;
  }}catch{w.message='Операция не завершена. Повторите проверку состояния.';}
  render();
 });
 render();return render;
}
