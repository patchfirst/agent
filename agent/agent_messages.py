"""English message keys and local display translations; inventory values never pass through this catalog."""
import os
import re
import sys

LANGUAGES = ('en', 'ru', 'de', 'fr', 'es')
_language = 'en'


def select(lang=None, environ=None):
    environment = os.environ if environ is None else environ
    if lang is not None:
        if lang not in LANGUAGES:
            raise ValueError(MESSAGES['Unsupported language: {language}. Allowed: en, ru, de, fr, es']['en'].format(language=lang))
        return lang
    preferred = environment.get('PATCHFIRST_LANG', '')
    if preferred in LANGUAGES:
        return preferred
    locale = next((environment.get(key, '') for key in ('LC_ALL', 'LC_MESSAGES', 'LANG') if environment.get(key)), '')
    if locale in ('C', 'POSIX'):
        return 'en'
    parts = locale.split('.', 1)
    if len(parts) > 1 and parts[1].split('@', 1)[0].lower().replace('-', '').replace('_', '') != 'utf8':
        return 'en'
    prefix = re.split(r'[_@-]', parts[0].lower(), maxsplit=1)[0]
    return prefix if prefix in LANGUAGES else 'en'


def configure(lang=None):
    global _language
    _language = select(lang)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', errors='replace')
            except (OSError, ValueError):
                pass
    return _language


def t(english, **params):
    template = MESSAGES.get(english, {}).get(_language, english)
    return template.format(**params) if params else template


_ROWS = [
    ('External', 'Внешний', 'Extern', 'Externe', 'Externa'),
    ('Local', 'Локальный', 'Lokal', 'Local', 'Local'),
    ('Global', 'Глобальный', 'Gesamt', 'Global', 'Global'),
    ('Expected', 'Ожидаемый', 'Erwartet', 'Attendu', 'Esperada'),
    ('* Expected: if reported risks are confirmed, allowing for unchecked software.',
     '* Ожидаемый: если заявленные угрозы подтвердятся, с учётом непроверенных компонентов.',
     '* Erwartet: falls gemeldete Risiken bestätigt werden, unter Berücksichtigung ungeprüfter Software.',
     '* Attendu : si les risques signalés sont confirmés, en tenant compte des logiciels non vérifiés.',
     '* Esperada: si se confirman los riesgos notificados, teniendo en cuenta el software sin comprobar.'),
    ('Local operation failed: {detail}', 'Локальная операция не удалась: {detail}', 'Lokaler Vorgang fehlgeschlagen: {detail}', 'Échec de l’opération locale : {detail}', 'La operación local falló: {detail}'),
    ('Invalid configuration or response: {detail}', 'Некорректная конфигурация или ответ: {detail}', 'Ungültige Konfiguration oder Antwort: {detail}', 'Configuration ou réponse invalide : {detail}', 'Configuración o respuesta no válida: {detail}'),
    ('Unsupported language: {language}. Allowed: en, ru, de, fr, es', 'Неподдерживаемый язык: {language}. Допустимы: en, ru, de, fr, es', 'Nicht unterstützte Sprache: {language}. Zulässig: en, ru, de, fr, es', 'Langue non prise en charge : {language}. Valeurs permises : en, ru, de, fr, es', 'Idioma no compatible: {language}. Permitidos: en, ru, de, fr, es'),
    ('Collection failed', 'Сбор не удался', 'Erfassung fehlgeschlagen', 'Échec de la collecte', 'La recopilación falló'),
    ('SSH timed out after {seconds} s', 'Время ожидания SSH истекло через {seconds} с', 'SSH-Zeitüberschreitung nach {seconds} s', 'Délai SSH dépassé après {seconds} s', 'Se agotó el tiempo de espera de SSH tras {seconds} s'),
    ('SSH exited with code {code}', 'SSH завершился с кодом {code}', 'SSH wurde mit Code {code} beendet', 'SSH s’est terminé avec le code {code}', 'SSH terminó con el código {code}'),
    ('{value}', '{value}', '{value}', '{value}', '{value}'),
    ('argument %(argument_name)s: %(message)s', 'аргумент %(argument_name)s: %(message)s', 'Argument %(argument_name)s: %(message)s', 'argument %(argument_name)s : %(message)s', 'argumento %(argument_name)s: %(message)s'),
    ('%(heading)s:', '%(heading)s:', '%(heading)s:', '%(heading)s :', '%(heading)s:'),
    ('ambiguous option: %(option)s could match %(matches)s', 'неоднозначный параметр: %(option)s соответствует %(matches)s', 'mehrdeutige Option: %(option)s könnte %(matches)s entsprechen', 'option ambiguë : %(option)s peut correspondre à %(matches)s', 'opción ambigua: %(option)s podría coincidir con %(matches)s'),
    ('ignored explicit argument %r', 'проигнорирован явный аргумент %r', 'explizites Argument %r ignoriert', 'argument explicite %r ignoré', 'argumento explícito %r ignorado'),
    ('expected at most one argument', 'ожидается не более одного аргумента', 'höchstens ein Argument erwartet', 'un argument au maximum attendu', 'se esperaba como máximo un argumento'),
    ('expected at least one argument', 'ожидается хотя бы один аргумент', 'mindestens ein Argument erwartet', 'au moins un argument attendu', 'se esperaba al menos un argumento'),
    ('Collect a server inventory, pseudonymize it locally, and send it to PatchFirst.', 'Собрать инвентарь сервера, псевдонимизировать его локально и отправить в PatchFirst.', 'Serverinventar erfassen, lokal pseudonymisieren und an PatchFirst senden.', "Collecter l’inventaire du serveur, le pseudonymiser localement et l’envoyer à PatchFirst.", 'Recopilar el inventario del servidor, seudonimizarlo localmente y enviarlo a PatchFirst.'),
    ('display language (en, ru, de, fr, es)', 'язык сообщений (en, ru, de, fr, es)', 'Anzeigesprache (en, ru, de, fr, es)', 'langue des messages (en, ru, de, fr, es)', 'idioma de los mensajes (en, ru, de, fr, es)'),
    ('show this help message and exit', 'показать справку и выйти', 'diese Hilfe anzeigen und beenden', 'afficher cette aide et quitter', 'mostrar esta ayuda y salir'),
    ("show program's version number and exit", 'показать версию программы и выйти', 'Programmversion anzeigen und beenden', 'afficher la version du programme et quitter', 'mostrar la versión del programa y salir'),
    ('usage: ', 'использование: ', 'Aufruf: ', 'utilisation : ', 'uso: '),
    ('positional arguments', 'позиционные аргументы', 'Positionsargumente', 'arguments positionnels', 'argumentos posicionales'),
    ('options', 'параметры', 'Optionen', 'options', 'opciones'),
    ('optional arguments', 'необязательные параметры', 'optionale Argumente', 'arguments facultatifs', 'argumentos opcionales'),
    ('%(prog)s: error: %(message)s\n', '%(prog)s: ошибка: %(message)s\n', '%(prog)s: Fehler: %(message)s\n', '%(prog)s : erreur : %(message)s\n', '%(prog)s: error: %(message)s\n'),
    ('the following arguments are required: %s', 'обязательные аргументы: %s', 'Folgende Argumente sind erforderlich: %s', 'les arguments suivants sont requis : %s', 'se requieren los siguientes argumentos: %s'),
    ('unrecognized arguments: %s', 'нераспознанные аргументы: %s', 'Unbekannte Argumente: %s', 'arguments inconnus : %s', 'argumentos desconocidos: %s'),
    ('argument %s: %s', 'аргумент %s: %s', 'Argument %s: %s', 'argument %s : %s', 'argumento %s: %s'),
    ('expected one argument', 'ожидается один аргумент', 'ein Argument erwartet', 'un argument attendu', 'se esperaba un argumento'),
    ('invalid choice: %(value)r (choose from %(choices)s)', 'недопустимое значение: %(value)r (выберите из %(choices)s)', 'Ungültige Auswahl: %(value)r (zur Auswahl: %(choices)s)', 'choix invalide : %(value)r (choisir parmi %(choices)s)', 'opción no válida: %(value)r (elige entre %(choices)s)'),
    ('project number for the local where command; omit to list projects', 'номер проекта для локальной команды where; без номера — список проектов', 'Projektnummer für den lokalen Befehl where; ohne Nummer alle Projekte auflisten', 'numéro du projet pour la commande locale where ; omettre pour lister les projets', 'número del proyecto para el comando local where; omitir para listar los proyectos'),
    ('also remove local project numbers on uninstall', 'при удалении также удалить локальные номера проектов', 'beim Deinstallieren auch lokale Projektnummern entfernen', 'supprimer aussi les numéros de projet locaux lors de la désinstallation', 'eliminar también los números de proyecto locales al desinstalar'),
    ('free check service URL', 'адрес сервиса бесплатной проверки', 'Dienstadresse für die kostenlose Prüfung', 'adresse du service de vérification gratuite', 'URL del servicio de comprobación gratuita'),
    ('check without network or a public package-name list', 'проверить без сети и списка публичных имён пакетов', 'ohne Netzwerk und Liste öffentlicher Paketnamen prüfen', 'vérifier sans réseau ni liste de noms de paquets publics', 'comprobar sin red ni lista de nombres de paquetes públicos'),
    ('show pseudonymized JSON without sending', 'показать псевдонимизированный JSON без отправки', 'pseudonymisiertes JSON ohne Versand anzeigen', 'afficher le JSON pseudonymisé sans envoi', 'mostrar el JSON seudonimizado sin enviarlo'),
    ('trusted CA certificate', 'доверенный сертификат центра сертификации', 'vertrauenswürdiges CA-Zertifikat', 'certificat d’autorité de confiance', 'certificado de CA de confianza'),
    ('collect over system SSH; only sh is required on the server', 'собрать через системный SSH; на сервере достаточно sh', 'über System-SSH erfassen; auf dem Server wird nur sh benötigt', 'collecter via le SSH du système ; seul sh est requis sur le serveur', 'recopilar mediante el SSH del sistema; solo se necesita sh en el servidor'),
    ('ssh -o setting, e.g. Port=2222 or IdentityFile=/path/key (repeatable)', 'параметр ssh -o, например Port=2222 или IdentityFile=/path/key (можно повторять)', 'ssh -o-Einstellung, z. B. Port=2222 oder IdentityFile=/path/key (wiederholbar)', 'option ssh -o, par exemple Port=2222 ou IdentityFile=/path/key (répétable)', 'opción ssh -o, p. ej. Port=2222 o IdentityFile=/path/key (repetible)'),
    ('--offline requires check --json', '--offline требует check --json', '--offline erfordert check --json', '--offline nécessite check --json', '--offline requiere check --json'),
    ('--purge is only used with uninstall', '--purge используется только с uninstall', '--purge ist nur mit uninstall zulässig', '--purge s’utilise uniquement avec uninstall', '--purge solo se usa con uninstall'),
    ('--ssh-opt requires --ssh', '--ssh-opt требует --ssh', '--ssh-opt erfordert --ssh', '--ssh-opt nécessite --ssh', '--ssh-opt requiere --ssh'),
    ('check requires --api or --json', 'check требует --api или --json', 'check erfordert --api oder --json', 'check nécessite --api ou --json', 'check requiere --api o --json'),
    ('project number is only used with where', 'номер проекта используется только с where', 'die Projektnummer ist nur mit where zulässig', 'le numéro de projet s’utilise uniquement avec where', 'el número de proyecto solo se usa con where'),
    ('project not found in the local list; run the run or dry-run command first', 'проект не найден в локальном списке; сначала выполните run или dry-run', 'Projekt nicht in der lokalen Liste gefunden; zuerst run oder dry-run ausführen', 'projet introuvable dans la liste locale ; exécuter d’abord run ou dry-run', 'proyecto no encontrado en la lista local; ejecuta primero run o dry-run'),
    ('server quota exhausted or payment required; open the dashboard', 'лимит серверов исчерпан или требуется оплата; откройте кабинет', 'Serverkontingent erschöpft oder Zahlung erforderlich; Dashboard öffnen', 'quota de serveurs épuisé ou paiement requis ; ouvrir le tableau de bord', 'cuota de servidores agotada o pago necesario; abre el panel'),
    ('check: API returned {status}{reason}', 'проверка: API вернул {status}{reason}', 'Prüfung: API meldet {status}{reason}', 'vérification : l’API a renvoyé {status}{reason}', 'comprobación: la API devolvió {status}{reason}'),
    ('timed out waiting for the service response', 'время ожидания ответа сервиса истекло', 'Zeitüberschreitung beim Warten auf die Dienstantwort', 'délai d’attente de la réponse du service dépassé', 'se agotó el tiempo de espera de la respuesta del servicio'),
    ('check service is unavailable or returned an invalid response', 'сервис проверки недоступен или вернул некорректный ответ', 'Prüfdienst nicht verfügbar oder ungültige Antwort', 'service de vérification indisponible ou réponse invalide', 'el servicio de comprobación no está disponible o devolvió una respuesta no válida'),
    ('check service returned an invalid response', 'сервис проверки вернул некорректный ответ', 'Prüfdienst lieferte eine ungültige Antwort', 'le service de vérification a renvoyé une réponse invalide', 'el servicio de comprobación devolvió una respuesta no válida'),
    ('timed out; open the report later', 'время ожидания истекло; откройте отчёт позже', 'Zeitüberschreitung; Bericht später öffnen', 'délai dépassé ; ouvrir le rapport plus tard', 'tiempo de espera agotado; abre el informe más tarde'),
    ('check service returned an invalid summary', 'сервис проверки вернул некорректную сводку', 'Prüfdienst lieferte eine ungültige Zusammenfassung', 'le service de vérification a renvoyé un résumé invalide', 'el servicio de comprobación devolvió un resumen no válido'),
    ('analysis failed; try the check again later', 'анализ не удался; повторите проверку позже', 'Analyse fehlgeschlagen; Prüfung später wiederholen', 'échec de l’analyse ; réessayer la vérification plus tard', 'el análisis falló; vuelve a comprobarlo más tarde'),
    ('check service returned an invalid status', 'сервис проверки вернул некорректный статус', 'Prüfdienst lieferte einen ungültigen Status', 'le service de vérification a renvoyé un statut invalide', 'el servicio de comprobación devolvió un estado no válido'),
    ('Collecting program versions...', 'Собираю версии программ…', 'Erfasse Programmversionen…', 'Collecte des versions des programmes…', 'Recopilando las versiones de los programas…'),
    ('Sending pseudonymized data...', 'Отправляю обезличенные данные…', 'Sende pseudonymisierte Daten…', 'Envoi des données pseudonymisées…', 'Enviando datos seudonimizados…'),
    ('Waiting for the analysis...', 'Жду анализ…', 'Warte auf die Analyse…', 'En attente de l’analyse…', 'Esperando el análisis…'),
    ('Waiting for the analysis... (queue position {position}, ~{minutes} min)', 'Жду анализ… (в очереди: позиция {position}, ~{minutes} мин)', 'Warte auf die Analyse… (Warteschlange: Position {position}, ~{minutes} Min.)', 'En attente de l’analyse… (file d’attente : position {position}, ~{minutes} min)', 'Esperando el análisis… (cola: posición {position}, ~{minutes} min)'),
    ('Analysis in progress... {seconds} s', 'Идёт анализ… {seconds} с', 'Analyse läuft… {seconds} s', 'Analyse en cours… {seconds} s', 'Análisis en curso… {seconds} s'),
    ('Full report (opens in a browser, kept for 7 days):', 'Полный отчёт (откроется в браузере, хранится 7 дней):', 'Vollständiger Bericht (öffnet sich im Browser, wird 7 Tage gespeichert):', 'Rapport complet (s’ouvre dans un navigateur, conservé 7 jours) :', 'Informe completo (se abre en el navegador, se conserva 7 días):'),
    ('Paid monitoring keeps watching this server: vulnerability IDs, the versions that fix them, and alerts when new ones appear.', 'Платный мониторинг следит за сервером постоянно: номера уязвимостей, версии с исправлениями и уведомления о новых.', 'Die kostenpflichtige Überwachung prüft den Server laufend: Kennungen der Schwachstellen, Versionen mit Korrektur und Benachrichtigungen bei neuen Funden.', 'La surveillance payante suit ce serveur en continu : identifiants des vulnérabilités, versions corrigées et alertes dès qu’il en apparaît de nouvelles.', 'La monitorización de pago vigila este servidor de forma continua: identificadores de vulnerabilidades, versiones que las corrigen y avisos cuando aparecen nuevas.'),
    ('Try again in a few minutes; instructions and other ways to check: {url}', 'Повторите через несколько минут; инструкция и другие способы проверки: {url}', 'In einigen Minuten erneut versuchen; Anleitung und weitere Prüfwege: {url}', 'Réessayez dans quelques minutes ; instructions et autres moyens de vérifier : {url}', 'Vuelve a intentarlo en unos minutos; instrucciones y otras formas de comprobar: {url}'),
    ('Unexpected error: {name}', 'Непредвиденная ошибка: {name}', 'Unerwarteter Fehler: {name}', 'Erreur inattendue : {name}', 'Error inesperado: {name}'),
    ('API {method} {path} returned {status}: {reason}', 'API {method} {path} вернул {status}: {reason}', 'API {method} {path} meldet {status}: {reason}', 'API {method} {path} a renvoyé {status} : {reason}', 'API {method} {path} devolvió {status}: {reason}'),
    ('API {url} is unavailable: {reason}', 'API {url} недоступен: {reason}', 'API {url} ist nicht verfügbar: {reason}', 'API {url} est indisponible : {reason}', 'API {url} no está disponible: {reason}'),
    ('could not obtain the public package-name list: components outside the catalogue were not checked', 'не удалось получить список публичных имён пакетов: компоненты вне каталога не проверены', 'Liste öffentlicher Paketnamen konnte nicht geladen werden: Komponenten außerhalb des Katalogs wurden nicht geprüft', 'impossible d’obtenir la liste des noms de paquets publics : les composants hors catalogue n’ont pas été vérifiés', 'no se pudo obtener la lista de nombres de paquetes públicos: los componentes fuera del catálogo no se comprobaron'),
    ('invalid public package-name list', 'некорректный список публичных имён пакетов', 'ungültige Liste öffentlicher Paketnamen', 'liste de noms de paquets publics invalide', 'lista de nombres de paquetes públicos no válida'),
    ('public package-name list is too large', 'список публичных имён пакетов слишком большой', 'Liste öffentlicher Paketnamen ist zu groß', 'liste de noms de paquets publics trop volumineuse', 'la lista de nombres de paquetes públicos es demasiado grande'),
    ('invalid local project list', 'некорректный локальный список проектов', 'ungültige lokale Projektliste', 'liste locale de projets invalide', 'lista local de proyectos no válida'),
    ('invalid SSH target: expected user@host or a name from ~/.ssh/config', 'некорректная цель SSH: укажите user@host или имя из ~/.ssh/config', 'ungültiges SSH-Ziel: user@host oder Namen aus ~/.ssh/config angeben', 'cible SSH invalide : utiliser user@host ou un nom de ~/.ssh/config', 'destino SSH no válido: usa user@host o un nombre de ~/.ssh/config'),
    ('invalid SSH option: expected a setting such as Port=2222', 'некорректный параметр SSH: укажите настройку вида Port=2222', 'ungültige SSH-Option: eine Einstellung wie Port=2222 angeben', 'option SSH invalide : utiliser un paramètre tel que Port=2222', 'opción SSH no válida: usa un ajuste como Port=2222'),
    ('OS description still contains an owner identity word; refusing to send', 'описание ОС содержит слово владельца; отправка отменена', 'Betriebssystembeschreibung enthält eine Eigentümerkennung; Versand abgelehnt', 'la description du système contient une identité du propriétaire ; envoi refusé', 'la descripción del sistema contiene una identidad del propietario; envío rechazado'),
    ('invalid anonymized JSON structure', 'некорректная структура псевдонимизированного JSON', 'ungültige Struktur des pseudonymisierten JSON', 'structure du JSON pseudonymisé invalide', 'estructura del JSON seudonimizado no válida'),
    ('anonymized JSON still contains a port key; refusing to send', 'JSON содержит поле порта; отправка отменена', 'JSON enthält noch ein Portfeld; Versand abgelehnt', 'le JSON contient encore un champ de port ; envoi refusé', 'el JSON todavía contiene un campo de puerto; envío rechazado'),
    ('unknown anonymized JSON field; refusing to send', 'неизвестное поле JSON; отправка отменена', 'unbekanntes JSON-Feld; Versand abgelehnt', 'champ JSON inconnu ; envoi refusé', 'campo JSON desconocido; envío rechazado'),
    ('process path is not a label; refusing to send', 'путь процесса не заменён меткой; отправка отменена', 'Prozesspfad ist keine Kennung; Versand abgelehnt', 'le chemin du processus n’est pas une étiquette ; envoi refusé', 'la ruta del proceso no es una etiqueta; envío rechazado'),
    ('invalid anonymized JSON list', 'некорректный список в JSON', 'ungültige JSON-Liste', 'liste JSON invalide', 'lista JSON no válida'),
    ('invalid anonymized JSON flag', 'некорректный логический признак в JSON', 'ungültiger JSON-Wahrheitswert', 'indicateur JSON invalide', 'indicador JSON no válido'),
    ('invalid anonymized JSON count', 'некорректный счётчик в JSON', 'ungültiger JSON-Zähler', 'compteur JSON invalide', 'recuento JSON no válido'),
    ('invalid anonymized JSON value; refusing to send', 'некорректное значение JSON; отправка отменена', 'ungültiger JSON-Wert; Versand abgelehnt', 'valeur JSON invalide ; envoi refusé', 'valor JSON no válido; envío rechazado'),
    ('anonymized JSON still contains: {values}; refusing to send', 'JSON всё ещё содержит: {values}; отправка отменена', 'JSON enthält weiterhin: {values}; Versand abgelehnt', 'le JSON contient encore : {values} ; envoi refusé', 'el JSON todavía contiene: {values}; envío rechazado'),
    ('low', 'низкий', 'niedrig', 'faible', 'bajo'),
    ('medium', 'средний', 'mittel', 'moyen', 'medio'),
    ('high', 'высокий', 'hoch', 'élevé', 'alto'),
    ('critical', 'критический', 'kritisch', 'critique', 'crítico'),
    ('clean', 'уязвимости не найдены', 'keine Schwachstellen gefunden', 'aucune vulnérabilité trouvée', 'sin vulnerabilidades encontradas'),
    ('unknown', 'неизвестно', 'unbekannt', 'inconnu', 'desconocido'),
    ('patchfirst: {message}', 'patchfirst: {message}', 'patchfirst: {message}', 'patchfirst: {message}', 'patchfirst: {message}'),
    ('patchfirst {version}', 'patchfirst {version}', 'patchfirst {version}', 'patchfirst {version}', 'patchfirst {version}'),
    ('{score}/100 ({grade})', '{score}/100 ({grade})', '{score}/100 ({grade})', '{score}/100 ({grade})', '{score}/100 ({grade})'),
    ('  {level} - {name} {version}', '  {level} - {name} {version}', '  {level} - {name} {version}', '  {level} - {name} {version}', '  {level} - {name} {version}'),
    ('{host} {score}/100 ({grade}) - P0 {p0} - P1 {p1} - P2 {p2}', '{host} {score}/100 ({grade}) - P0 {p0} - P1 {p1} - P2 {p2}', '{host} {score}/100 ({grade}) - P0 {p0} - P1 {p1} - P2 {p2}', '{host} {score}/100 ({grade}) - P0 {p0} - P1 {p1} - P2 {p2}', '{host} {score}/100 ({grade}) - P0 {p0} - P1 {p1} - P2 {p2}'),
    ('{number}\t{path}', '{number}\t{path}', '{number}\t{path}', '{number}\t{path}', '{number}\t{path}'),
]
MESSAGES = {row[0]: dict(zip(LANGUAGES, row)) for row in _ROWS}

# Installer diagnostics share the agent language and English source keys.
INSTALL_MESSAGES = {
    'unsafe migration lock owner or type': {'en': 'unsafe migration lock owner or type', 'ru': 'Небезопасный владелец или тип блокировки миграции', 'de': 'Unsicherer Eigentümer oder Typ der Migrationssperre', 'fr': 'Propriétaire ou type de verrou de migration non sûr', 'es': 'Propietario o tipo de bloqueo de migración inseguro'},
    'unsafe migration state owner or type': {'en': 'unsafe migration state owner or type', 'ru': 'Небезопасный владелец или тип состояния миграции', 'de': 'Unsicherer Eigentümer oder Typ des Migrationsstatus', 'fr': 'Propriétaire ou type d’état de migration non sûr', 'es': 'Propietario o tipo de estado de migración inseguro'},
    'crontab -l did not respond within 10 s': {'en': 'crontab -l did not respond within 10 s', 'ru': 'crontab -l не ответил за 10 с', 'de': 'crontab -l antwortete nicht innerhalb von 10 s', 'fr': 'crontab -l n’a pas répondu en 10 s', 'es': 'crontab -l no respondió en 10 s'},
    'two cron jobs found: patchfirst and psr-agent; sending canceled: reinstall using the command from the dashboard to keep a single job': {'en': 'two cron jobs found: patchfirst and psr-agent; sending canceled: reinstall using the command from the dashboard to keep a single job', 'ru': 'Найдены два задания cron: patchfirst и psr-agent; отправка отменена: переустановите командой из кабинета, чтобы оставить одно задание', 'de': 'Zwei Cron-Aufträge gefunden: patchfirst und psr-agent; Versand abgebrochen: mit dem Dashboard-Befehl neu installieren, um einen Auftrag zu behalten', 'fr': 'Deux tâches cron détectées : patchfirst et psr-agent ; envoi annulé : réinstallez avec la commande du tableau de bord pour conserver une seule tâche', 'es': 'Se encontraron dos tareas cron: patchfirst y psr-agent; envío cancelado: reinstala con el comando del panel para mantener una sola tarea'},
    'waiting for the running agent exceeded {timeout} seconds; cleanup canceled, retry after the agent finishes': {'en': 'waiting for the running agent exceeded {timeout} seconds; cleanup canceled, retry after the agent finishes', 'ru': 'Ожидание работающего агента превысило {timeout} секунд; очистка отменена, повторите после завершения агента', 'de': 'Warten auf den laufenden Agenten dauerte länger als {timeout} Sekunden; Bereinigung abgebrochen, nach Abschluss erneut versuchen', 'fr': 'L’attente de l’agent actif dépasse {timeout} secondes ; nettoyage annulé, réessayez après sa fin', 'es': 'La espera del agente en ejecución superó {timeout} segundos; limpieza cancelada, reintenta cuando termine'},
    'an http(s) API URL without a username is required': {'en': 'an http(s) API URL without a username is required', 'ru': 'Нужен http(s)-адрес API без имени пользователя', 'de': 'Eine http(s)-API-Adresse ohne Benutzernamen ist erforderlich', 'fr': 'Une URL API http(s) sans nom d’utilisateur est requise', 'es': 'Se requiere una URL API http(s) sin nombre de usuario'},
    'the API URL must not contain a query or fragment': {'en': 'the API URL must not contain a query or fragment', 'ru': 'Адрес API не должен содержать запрос или фрагмент', 'de': 'Die API-Adresse darf weder Abfrage noch Fragment enthalten', 'fr': 'L’URL API ne doit contenir ni requête ni fragment', 'es': 'La URL API no debe contener consulta ni fragmento'},
    'HTTPS is required for a remote API': {'en': 'HTTPS is required for a remote API', 'ru': 'Для удалённого API нужен HTTPS', 'de': 'HTTPS ist für eine entfernte API erforderlich', 'fr': 'HTTPS est requis pour une API distante', 'es': 'Se requiere HTTPS para una API remota'},
    'config must be an object': {'en': 'config must be an object', 'ru': 'Конфиг должен быть объектом', 'de': 'Die Konfiguration muss ein Objekt sein', 'fr': 'La configuration doit être un objet', 'es': 'La configuración debe ser un objeto'},
    'missing field {field}': {'en': 'missing field {field}', 'ru': 'Отсутствует поле {field}', 'de': 'Feld {field} fehlt', 'fr': 'Champ {field} manquant', 'es': 'Falta el campo {field}'},
    'the agent must be downloaded from the API domain': {'en': 'the agent must be downloaded from the API domain', 'ru': 'Агент должен скачиваться с домена API', 'de': 'Der Agent muss von der API-Domain heruntergeladen werden', 'fr': 'L’agent doit être téléchargé depuis le domaine de l’API', 'es': 'El agente debe descargarse desde el dominio de la API'},
    'invalid agent size': {'en': 'invalid agent size', 'ru': 'Неверный размер агента', 'de': 'Ungültige Agentengröße', 'fr': 'Taille de l’agent non valide', 'es': 'Tamaño del agente no válido'},
    'the downloaded agent is not a zip archive': {'en': 'the downloaded agent is not a zip archive', 'ru': 'Скачанный агент не является zip-архивом', 'de': 'Der heruntergeladene Agent ist kein ZIP-Archiv', 'fr': 'L’agent téléchargé n’est pas une archive ZIP', 'es': 'El agente descargado no es un archivo ZIP'},
    'invalid binary name': {'en': 'invalid binary name', 'ru': 'Неверное имя бинарника', 'de': 'Ungültiger Binärdateiname', 'fr': 'Nom de binaire non valide', 'es': 'Nombre de binario no válido'},
    'SHA-256 mismatch, installation canceled': {'en': 'SHA-256 mismatch, installation canceled', 'ru': 'SHA-256 не совпадает, установка отменена', 'de': 'SHA-256 stimmt nicht überein, Installation abgebrochen', 'fr': 'SHA-256 ne correspond pas, installation annulée', 'es': 'SHA-256 no coincide, instalación cancelada'},
    'config in b64url format is required': {'en': 'config in b64url format is required', 'ru': 'Нужен конфиг в формате b64url', 'de': 'Eine Konfiguration im b64url-Format ist erforderlich', 'fr': 'Une configuration au format b64url est requise', 'es': 'Se requiere una configuración en formato b64url'},
    'config.api does not match the installer download URL': {'en': 'config.api does not match the installer download URL', 'ru': 'config.api не совпадает с адресом загрузки установщика', 'de': 'config.api stimmt nicht mit der Download-Adresse des Installers überein', 'fr': 'config.api ne correspond pas à l’URL de téléchargement de l’installateur', 'es': 'config.api no coincide con la URL de descarga del instalador'},
    'newline in path': {'en': 'newline in path', 'ru': 'Перевод строки в пути', 'de': 'Zeilenumbruch im Pfad', 'fr': 'Saut de ligne dans le chemin', 'es': 'Salto de línea en la ruta'},
    'invalid cron schedule': {'en': 'invalid cron schedule', 'ru': 'Неверное расписание cron', 'de': 'Ungültiger Cron-Zeitplan', 'fr': 'Planification cron non valide', 'es': 'Programación cron no válida'},
    'patchfirst: installation failed: {error}': {'en': 'patchfirst: installation failed: {error}', 'ru': 'patchfirst: установка не удалась: {error}', 'de': 'patchfirst: Installation fehlgeschlagen: {error}', 'fr': 'patchfirst: échec de l’installation : {error}', 'es': 'patchfirst: falló la instalación: {error}'},
    'project registry conflict; operation stopped': {'en': 'project registry conflict; operation stopped', 'ru': 'Конфликт реестра проектов; операция остановлена', 'de': 'Konflikt im Projektregister; Vorgang angehalten', 'fr': 'Conflit de registre de projets ; opération arrêtée', 'es': 'Conflicto en el registro de proyectos; operación detenida'},
    'patchfirst: directory {directory} retained: contains other files': {'en': 'patchfirst: directory {directory} retained: contains other files', 'ru': 'patchfirst: каталог {directory} оставлен: содержит другие файлы', 'de': 'patchfirst: Verzeichnis {directory} beibehalten: enthält andere Dateien', 'fr': 'patchfirst: répertoire {directory} conservé : contient d’autres fichiers', 'es': 'patchfirst: directorio {directory} conservado: contiene otros archivos'},
    'patchfirst: monitoring removed': {'en': 'patchfirst: monitoring removed', 'ru': 'patchfirst: мониторинг удалён', 'de': 'patchfirst: Überwachung entfernt', 'fr': 'patchfirst: surveillance supprimée', 'es': 'patchfirst: monitorización eliminada'},
    'config conflict: secret or host_uuid; migration stopped': {'en': 'config conflict: secret or host_uuid; migration stopped', 'ru': 'Конфликт конфига: secret или host_uuid; миграция остановлена', 'de': 'Konfigurationskonflikt: secret oder host_uuid; Migration angehalten', 'fr': 'Conflit de configuration : secret ou host_uuid ; migration arrêtée', 'es': 'Conflicto de configuración: secret o host_uuid; migración detenida'},
}
MESSAGES.update(INSTALL_MESSAGES)
