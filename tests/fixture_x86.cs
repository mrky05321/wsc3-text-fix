using System;
using System.Runtime.InteropServices;
public static class WrapFixture {
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
 [DllImport("kernel32.dll")]
 static extern bool FlushInstructionCache(IntPtr process,IntPtr address,UIntPtr size);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int Routine();
 public static IntPtr Renderer, Code;
 public static Routine Call;
 public static void Initialize() {
  if(IntPtr.Size!=4) throw new Exception("32-bit fixture required");
  Renderer=VirtualAlloc(IntPtr.Zero,(UIntPtr)0x2000,0x3000,4);
  Code=VirtualAlloc(IntPtr.Zero,(UIntPtr)4096,0x3000,0x40);
  if(Renderer==IntPtr.Zero || Code==IntPtr.Zero) throw new Exception("Allocation failed");
  Marshal.WriteInt32(Renderer,0x5a6264);
  Marshal.WriteInt32(Renderer,0x53c,Renderer.ToInt32()+0xd44);
  byte[] code=new byte[]{0x55,0xbd,0,0,0,0,0x81,0xec,0,0x0a,0,0,
   0xc7,0x84,0x24,0x88,0,0,0,24,0,0,0,
   0x8b,0x8c,0x24,0x88,0,0,0,0x8b,0xc1,0x81,0xc4,0,0x0a,0,0,0x5d,0xc3};
  Array.Copy(BitConverter.GetBytes(Renderer.ToInt32()),0,code,2,4);
  Marshal.Copy(code,0,Code,code.Length);
  FlushInstructionCache(new IntPtr(-1),Code,(UIntPtr)code.Length);
  Call=(Routine)Marshal.GetDelegateForFunctionPointer(Code,typeof(Routine));
 }
 public static int Evaluate(int height,int width) {
  Marshal.WriteInt32(Renderer,0x464,height);
  Marshal.WriteInt32(Code,19,width);
  FlushInstructionCache(new IntPtr(-1),Code,(UIntPtr)40);
  return Call();
 }

 public static void Main() {
  Initialize();
  Console.WriteLine("{\"pid\":"+System.Diagnostics.Process.GetCurrentProcess().Id+",\"site\":"+(Code.ToInt32()+23)+",\"vtable\":5923428}");
  Console.Out.Flush();
  string line;
  while((line=Console.ReadLine())!=null) {
   if(line=="quit") break;
   string[] parts=line.Split(',');
   Console.WriteLine(Evaluate(Int32.Parse(parts[0]),Int32.Parse(parts[1])));
   Console.Out.Flush();
  }
 }
}
