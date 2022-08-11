(*
Directions for creating a service were from here:
  https://fsharpwindowsservices.wordpress.com/2019/10/31/creating-a-basic-windows-service/
*)
module Loginwatcher.Program

open System.Threading.Tasks
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Microsoft.Extensions.Logging.EventLog

open Loginwatcher.Worker
open System.Threading

type ServiceWorker (logger: ILogger<ServiceWorker>) =
  inherit BackgroundService()
  override this.ExecuteAsync(stoppingToken: CancellationToken) =
    async { runAsService stoppingToken logger }
    |> Async.StartAsTask :> Task

let createHostBuilder args =
  let configureLogging (builder: ILoggingBuilder) =
    builder.AddFilter<EventLogLoggerProvider>(fun level -> level >= LogLevel.Information)
    |> ignore
  in
  let configureServices _ (services : IServiceCollection) =
    services.AddHostedService<ServiceWorker>()
      .Configure(fun (cfg: EventLogSettings) ->
        cfg.LogName <- "loginwatcher Service"
        cfg.SourceName <- "loginwatcher Service Source")
      |> ignore
  in
  Host.CreateDefaultBuilder(args)
    .UseWindowsService()
    .ConfigureLogging(configureLogging)
    .ConfigureServices(configureServices)
    
[<EntryPoint>]
let main = function
  | [| "-console" |] -> Worker.runAsConsoleApp ()
  | argv -> (createHostBuilder argv).Build().Run(); 0
(*
type WorkerWrap (logger : ILogger<WorkerWrap>) =
  inherit BackgroundService()
  let logger = logger
  override bs.ExecuteAsync stoppingToken =
    let f : Async<unit> = async {
      Worker.Work.start logger;
      (*
      while not stoppingToken.IsCancellationRequested do
        logger.LogInformation("Worker running at: {time}", DateTime.Now)
        do! Async.Sleep(1000)
        *)
    }
    Async.StartAsTask f :> Task
*)
(*
module Installer =
  let getInstaller() =
    let installer = new AssemblyInstaller(typedefof<atf>.Assembly, null);
    installer.UseNewContext <- true
    installer

  let installService() =
    let installer = getInstaller()
    let dic = new System.Collections.Hashtable()
    installer.Install(dic)
    installer.Commit(dic)

  let uninstallService() =
    let installer = getInstaller()
    let dic = new System.Collections.Hashtable()
    installer.Uninstall(dic)
*)

(*
[<EntryPoint>]
let main (args:string[]) = 
  match (args |> Seq.length) with
  | 1 ->
    match (args.[0]) with
    |"-install" -> Installer.installService ()
    |"-uninstall" -> uninstallService()
    |_-> failwith "Unrecognized param %s" args.[0]
  | _ ->
    ServiceBase.Run [| new atf() :> ServiceBase |]
  0v
*)