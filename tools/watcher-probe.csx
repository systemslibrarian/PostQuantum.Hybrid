// Quick FileSystemWatcher diagnostic. Usage:
//   dotnet script tools/watcher-probe.csx
// Watches a temp dir for writes; touches a file after 2s; reports events.
using System;
using System.IO;
using System.Threading;

var dir = Path.Combine(Path.GetTempPath(), "fsw-probe-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(dir);
var path = Path.Combine(dir, "probe.txt");
File.WriteAllText(path, "initial");

Console.WriteLine($"Watching: {dir}");

var w = new FileSystemWatcher(dir, "probe.txt")
{
    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
    EnableRaisingEvents = true,
};
w.Changed += (s, e) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Changed: {e.FullPath}");
w.Created += (s, e) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Created: {e.FullPath}");
w.Renamed += (s, e) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Renamed: {e.FullPath}");
w.Error += (s, e) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Error: {e.GetException()}");

Thread.Sleep(2000);
Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] writing...");
File.WriteAllText(path, "second");
Thread.Sleep(3000);
Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] writing again...");
File.WriteAllText(path, "third");
Thread.Sleep(3000);
Console.WriteLine("done.");
