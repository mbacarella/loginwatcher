module Loginwatcher.Worker

open System
open System.Diagnostics
open System.Security.Principal
open System.Threading
open System.Text.RegularExpressions
open System.Collections.Generic

open System
open System.Threading
open System.Threading.Tasks
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging

type LogLevel = Info | Warn 

module Settings =
  (* configuration section *)
  let ipWhitelist = [
    "127.0.0.1";
    (* home ip *)
    (* work ip *)
  ]

  let mailEnvelopeSender = "admin@example.com"

  let smtpUser = "USERNAME"
  let smtpPassword = "PASSWORD"
  let smtpServer = "smtp-relay.example.com"
  let smtpPort = 1025
  let smtpUseTls = true
  let ruleName = "AUTO_BANNED"

  let failureToBanThreshold = 100
  let statusPrintingInterval = 60 (* seconds *)

  let securityEventLog = "security"

module Mail =
  open System.Net.Mail
  let send logger recipient subject msg =
    let msg = new MailMessage (Settings.mailEnvelopeSender, recipient, subject, msg) in
    msg.IsBodyHtml <- true
    let client = new SmtpClient(Settings.smtpServer, Settings.smtpPort)
    client.EnableSsl <- Settings.smtpUseTls;
    client.Credentials <- System.Net.NetworkCredential (Settings.smtpUser, Settings.smtpPassword)
    client.SendCompleted |> Observable.add(fun e -> 
      let msg = e.UserState :?> MailMessage
      if e.Cancelled then logger Warn (sprintf "send to %s was cancelled" recipient);
      if not (isNull e.Error) then logger Warn (sprintf "send to %s failed: %s" recipient (e.Error.ToString ()));
      if msg <> Unchecked.defaultof<MailMessage> then msg.Dispose();
      if client <> Unchecked.defaultof<SmtpClient> then client.Dispose()
    );
    client.SendAsync (msg, msg)

module ShellDispatch =
  let runShellCommand logger cmdline = 
    use p = new System.Diagnostics.Process () in
    let si = System.Diagnostics.ProcessStartInfo () in
    si.WindowStyle <- System.Diagnostics.ProcessWindowStyle.Hidden;
    si.FileName <- "cmd.exe";
    si.Arguments <- sprintf "/C %s" cmdline;
    p.StartInfo <- si;
    if not (p.Start ())
    then logger Warn (sprintf "failed to run shell command: %s" cmdline)
    else p.WaitForExit ()

  let banIp logger ip =
    if List.contains ip Settings.ipWhitelist
    then logger Info (sprintf "refusing to ban ip %s; it's on the whitelist!" ip)
    else begin
      let cmdline =
        sprintf "netsh advfirewall firewall add rule name=\"%s\" interface=any dir=in action=block remoteip=%s/32"
          Settings.ruleName ip
      in
      runShellCommand logger cmdline;
      logger Info (sprintf "IP %s was BANNED" ip)
    end

  let clearAllBans logger =
    logger Info "startup: clearing all bans";
    let cmdline =
      sprintf "netsh advfirewall firewall delete rule name=\"%s\"" Settings.ruleName
    in
    runShellCommand logger cmdline


type State = {
  StartTime : DateTime;
  LogonFails : Dictionary<string, int>;
  mutable BannedIps : Set<string>;
  EventLog : EventLog;
  Logger : (LogLevel -> string -> unit);
  UserSeenIps : Dictionary<string, string list>;
}

module Work =
  let logEventLogEntry logger (ent : EventLogEntry) =
    List.iter (fun line -> logger Info line)
      [ sprintf "* NEW SECURITY ENTRY" ;
        sprintf "  ID: %d" ent.InstanceId;
        sprintf "  USERNAME: %s" ent.UserName;
        sprintf "  CATEGORY: %s / %d" ent.Category ent.CategoryNumber;
        sprintf "  TIME: %s" (ent.TimeGenerated.ToString ());
        sprintf "  TYPE: %s" (ent.EntryType.ToString ());
        sprintf "  SOURCE: %s" ent.Source;
        sprintf "  DATA: %s" (ent.Data.ToString ());
        sprintf "  MSG prefix: %s" (ent.Message.[0..1200]) ]

  let sourceIpRex =
    Regex ("^.*Source Network Address:[^0-9]+([0-9\\.]+)", RegexOptions.Multiline)
  let sourcePortRex =
    Regex ("^.*Source Port:[^0-9]+([0-9\\.]+)", RegexOptions.Multiline)
  let logonTypeRex =
    Regex ("^.*Logon Type:[^0-9]+([0-9]+)", RegexOptions.Multiline)
  let accountNameRex =
    Regex ("^.*Account Name:[^a-zA-Z0-9\\.]+([a-zA-Z0-9\\.]+)", RegexOptions.Multiline)

  let matchSingleRex (rex : Regex) (msg : string) =
    let m = rex.Match msg in
    if m.Groups.Count <> 2 then None
    else Some m.Groups.[1].Value

  let notifyLogin logger username ip =
    let subject = sprintf "%s logged in from new location %s" username ip in
    logger Info subject;
    Mail.send logger "m.bacarella@imerusa.com" subject "[eom]"

  let eventReceived (state : State) (ewea : EntryWrittenEventArgs) =
    let ent = ewea.Entry in
    let msg = ent.Message in
    match ent.EntryType.ToString () with
    | "FailureAudit" ->
      if not (msg.StartsWith "An account failed to log on.") then ()
      else begin
        match matchSingleRex sourceIpRex msg with
        | None -> ()
        | Some ip ->
          let shouldBan =
            lock state (fun () ->
              let () =
                state.LogonFails.[ip] <-
                  if state.LogonFails.ContainsKey ip
                  then state.LogonFails.[ip] + 1
                  else 1
              in
              if state.LogonFails.[ip] >= Settings.failureToBanThreshold && not (state.BannedIps.Contains ip)
              then begin
                state.BannedIps <- state.BannedIps.Add ip;
                true
              end else false)
          in
          if shouldBan then
            Async.Start (async { ShellDispatch.banIp state.Logger ip })
      end
    | "SuccessAudit" ->
      begin match matchSingleRex logonTypeRex msg with
      | None -> ()
      | Some logonType ->
        begin match int logonType with
        | 2 -> () (* local account logins/outs *)
        | 3 -> () (* network folder access *)
        | 4 -> () (* scheduled task *)
        | 5 -> () (* service startup *)
        | 7 -> () (* unlock *)
        | 8 -> () (* network cleartext login *) 
        | 11 -> () (* cached interactive login *)
        | 10 -> (* remote desktop *)
          begin match matchSingleRex sourceIpRex msg with
          | None -> ()
          | Some ip ->
            state.Logger Info "process remote logon message";
            let newLogonIndex = msg.IndexOf "New Logon:" in
            if newLogonIndex <= 0 then () (* skip an 'Account Name:' earlier on *)
            else begin
              match matchSingleRex accountNameRex msg.[newLogonIndex..] with
              | None ->
                state.Logger Warn "could not match account names in SuccessAudit message";
                logEventLogEntry state.Logger ent
              | Some username ->
                state.Logger Info (sprintf "successful login for %s from IP: %s" username ip);
                let shouldNotify =
                  lock state (fun () ->
                    state.LogonFails.[ip] <- 0;
                    if state.UserSeenIps.ContainsKey username then begin
                      if List.contains ip state.UserSeenIps.[username] then false
                      else begin
                        state.UserSeenIps.[username] <- ip :: state.UserSeenIps.[username];
                        true
                      end
                    end else begin
                      state.UserSeenIps.[username] <- [ip];
                      true
                    end)
                in
                if shouldNotify then begin
                  if List.contains ip Settings.ipWhitelist then ()
                  else Async.Start (async { notifyLogin state.Logger username ip } )
                end
            end
          end
        | unknownLogonType ->
          state.Logger Info (sprintf "Logon message with unknown type: %d" unknownLogonType);
          logEventLogEntry state.Logger ent
        end
      end
    | other ->
      state.Logger Info (sprintf "Unknown event type: %s" other);
      logEventLogEntry state.Logger ent

  let startEventLogWatcher (state : State) =
    state.EventLog.EnableRaisingEvents <- true;
    state.Logger Info (sprintf "startup complete; listening to %s EventLog" Settings.securityEventLog);
    state.EventLog.EntryWritten.Add (fun ewea ->
      try eventReceived state ewea
      with e ->
        state.Logger Warn (sprintf "exception raised handling EventLog entry: %s" (e.ToString ()))
    )
  
  let elevatePrivileges logger  =
    let p = System.Diagnostics.Process.GetCurrentProcess () in
    let exe = p.MainModule.FileName in
    let si = ProcessStartInfo exe in
    si.Verb <- "runas";
    si.Arguments <- "-console";
    si.UseShellExecute <- true;
    ignore (System.Diagnostics.Process.Start si)

  let logStatusInfo (state : State) =
    let statusInfo =
      lock state (fun () ->
        let nBanned = Set.count state.BannedIps in
        let nTracked = state.LogonFails.Count in
        let nUsers = state.UserSeenIps.Count in
        let loggedInUsers =
          List.map (fun user ->
            let ips = String.concat "," state.UserSeenIps.[user] in
            sprintf " %s: %s" user ips)
            (List.ofSeq state.UserSeenIps.Keys)
        in      
        sprintf "STATUS UPDATE: %d banned ips, %d tracked; %d users\n%s"
          nBanned nTracked nUsers (String.concat "\n" loggedInUsers))
    in
    state.Logger Info statusInfo

  let startNormally logger =
    let state = 
      {
        StartTime = DateTime ();
        LogonFails = Dictionary ();
        BannedIps = Set [];
        EventLog = new System.Diagnostics.EventLog (Settings.securityEventLog, ".");
        Logger = logger;
        UserSeenIps = Dictionary ();
      }
    in
    ShellDispatch.clearAllBans logger;
    startEventLogWatcher state;
    Mail.send logger "m.bacarella@imerusa.com" "loginwatcher started normally" "[eom]";
    while true do
      Thread.Sleep (Settings.statusPrintingInterval * 1000);
      logStatusInfo state

let runAsConsoleApp () =
  let logConsole level msg =
    match level with
    | Info -> printfn "INFO: %s" msg
    | Warn -> printfn "WARN: %s" msg
  in
  let isAdministrator =
    let id = WindowsIdentity.GetCurrent () in
    let p = WindowsPrincipal id in
    p.IsInRole WindowsBuiltInRole.Administrator
  in
  let () =
    if not isAdministrator then begin
      logConsole Info "not admin; restarting with UAC prompt";
      Work.elevatePrivileges logConsole
    end else begin
      Work.startNormally logConsole
    end
  in
  0

let runAsService (stoppingToken: CancellationToken) (logger: ILogger) =
  let logToEventLog level msg =
    let level =
      match level with
      | Info -> LogLevel.Information
      | Warn -> LogLevel.Warning
    in
    logger.Log (level, msg)
  in
  Work.startNormally logToEventLog