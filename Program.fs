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