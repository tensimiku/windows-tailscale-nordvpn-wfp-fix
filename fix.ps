<#
.SYNOPSIS
    Fixes Tailscale traffic & MagicDNS being blocked when running alongside NordVPN on Windows.

.DESCRIPTION
    NordVPN's NDivert WFP driver (NDivert.sys / NDivertControl.dll) registers static
    FWP_ACTION_BLOCK filters in "NordVPN split tunnel sublayer" (weight 34212 / 0x85A4)
    that miss 100.64.0.0/10 (Tailscale CGNAT) and block port 53 DNS (MagicDNS) except
    NordLynx DNS, while LeakGuard unconditionally disables IPv6 on non-NordVPN adapters.

    This script creates a high-priority persistent WFP provider & sublayer (weight 0xFFFF = 65535)
    with FWP_ACTION_PERMIT + FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT ("Hard Permit") for:
      1. IPv4 100.64.0.0/10 (all Tailscale peer IPs + MagicDNS 100.100.100.100)
      2. IPv6 fd7a:115c:a1e0::/48 (Tailscale ULA peers + MagicDNS fd7a:115c:a1e0::53)
      3. Tailscale virtual adapter Interface LUID (covers subnet routers / custom routes)
    across all 6 NDivert enforcement layers (ALE_AUTH_CONNECT_V4/V6,
    ALE_AUTH_RECV_ACCEPT_V4/V6, DATAGRAM_DATA_V4/V6), leaving NordVPN Kill Switch and
    DNS Leak Protection intact for all non-Tailscale traffic.

.PARAMETER Action
    Install      : Install persistent WFP Hard-Permit filters and restore Tailscale IPv6 binding (Admin required).
    Uninstall    : Remove all WFP filters, sublayer, and provider installed by this script (Admin required).
    Status       : Show adapter IPv6 binding status and installed WFP rule state.
    RestoreIpv6  : Re-enable IPv6 binding (ms_tcpip6) on the Tailscale adapter after NordVPN reconnects (Admin required).
    Validate     : Offline self-test of P/Invoke struct layout (size/offset) and CIDR encoding (no Admin needed).

.PARAMETER IncludeInterfaceRule
    Also permit traffic routed to the local Tailscale adapter Interface LUID (default: $true).

.PARAMETER RestoreIpv6
    Re-enable ms_tcpip6 on the Tailscale adapter during Install (default: $true).

.EXAMPLE
    .\TailscaleNordVpnFix.ps1 -Action Install
.EXAMPLE
    .\TailscaleNordVpnFix.ps1 -Action Status
.EXAMPLE
    .\TailscaleNordVpnFix.ps1 -Action Uninstall
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status', 'RestoreIpv6', 'Validate')]
    [string]$Action = 'Install',

    [bool]$IncludeInterfaceRule = $true,

    [bool]$RestoreIpv6 = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CSharpSource = @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace TailscaleNordVpnWfp
{
    public static class WfpConst
    {
        public const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFFu;

        public const uint FWP_E_FILTER_NOT_FOUND   = 0x80320003u;
        public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005u;
        public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007u;
        public const uint FWP_E_ALREADY_EXISTS     = 0x80320009u;
        public const uint ERROR_ACCESS_DENIED      = 5u;

        public const uint FWP_EMPTY        = 0u;
        public const uint FWP_UINT8        = 1u;
        public const uint FWP_UINT64       = 4u;
        public const uint FWP_V4_ADDR_MASK = 0x100u;
        public const uint FWP_V6_ADDR_MASK = 0x101u;

        public const uint FWP_MATCH_EQUAL = 0u;

        public const uint FWP_ACTION_PERMIT = 0x00001002u; // 0x2 | FWP_ACTION_FLAG_TERMINATING (0x1000)

        public const uint FWPM_PROVIDER_FLAG_PERSISTENT       = 0x00000001u;
        public const uint FWPM_SUBLAYER_FLAG_PERSISTENT       = 0x00000001u;
        public const uint FWPM_FILTER_FLAG_PERSISTENT         = 0x00000001u;
        public const uint FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x00000008u;

        public static readonly Guid ProviderKey = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0001");
        public static readonly Guid SubLayerKey = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0002");

        public static readonly Guid LAYER_ALE_AUTH_CONNECT_V4     = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid LAYER_ALE_AUTH_CONNECT_V6     = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid LAYER_ALE_AUTH_RECV_ACCEPT_V4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid LAYER_ALE_AUTH_RECV_ACCEPT_V6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        public static readonly Guid LAYER_DATAGRAM_DATA_V4        = new Guid("3d08bf4e-45f6-4930-a922-417098e20027");
        public static readonly Guid LAYER_DATAGRAM_DATA_V6        = new Guid("fa45fe2f-3cba-4427-87fc-57b9a4b10d00");

        public static readonly Guid CONDITION_IP_REMOTE_ADDRESS  = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid CONDITION_IP_LOCAL_INTERFACE = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");

        // Deterministic filter keys (v4 CGNAT, v6 ULA, v4 IfLuid, v6 IfLuid across 3 layers each)
        public static readonly Guid FILTER_V4_CIDR_CONNECT  = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0101");
        public static readonly Guid FILTER_V4_CIDR_RECV     = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0102");
        public static readonly Guid FILTER_V4_CIDR_DATAGRAM = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0103");

        public static readonly Guid FILTER_V6_CIDR_CONNECT  = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0201");
        public static readonly Guid FILTER_V6_CIDR_RECV     = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0202");
        public static readonly Guid FILTER_V6_CIDR_DATAGRAM = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0203");

        public static readonly Guid FILTER_V4_IF_CONNECT    = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0301");
        public static readonly Guid FILTER_V4_IF_RECV       = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0302");
        public static readonly Guid FILTER_V4_IF_DATAGRAM   = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0303");

        public static readonly Guid FILTER_V6_IF_CONNECT    = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0401");
        public static readonly Guid FILTER_V6_IF_RECV       = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0402");
        public static readonly Guid FILTER_V6_IF_DATAGRAM   = new Guid("8B4B7D1A-2B9E-4D6A-9E3A-1F8C9B7D0403");
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] addr;
        public byte prefixLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct FWP_VALUE_UNION
    {
        [FieldOffset(0)] public byte uint8;
        [FieldOffset(0)] public ushort uint16;
        [FieldOffset(0)] public uint uint32;
        [FieldOffset(0)] public IntPtr ptr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_VALUE0
    {
        public uint type;
        public FWP_VALUE_UNION val;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_CONDITION_VALUE0
    {
        public uint type;
        public FWP_VALUE_UNION val;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_DISPLAY_DATA0
    {
        public IntPtr name;
        public IntPtr description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public IntPtr sid;
        public IntPtr username;
        public int kernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public FWP_BYTE_BLOB providerData;
        public IntPtr serviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct FWPM_FILTER_CONTEXT_UNION
    {
        [FieldOffset(0)] public ulong rawContext;
        [FieldOffset(0)] public Guid providerContextKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public FWPM_FILTER_CONTEXT_UNION context;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    internal static class NativeMethods
    {
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmEngineOpen0(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint authnService,
            IntPtr authIdentity,
            IntPtr session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmProviderGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr provider);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmFilterGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr filter);
    }

    public sealed class FilterSpec
    {
        public Guid Key;
        public string Name;
        public Guid LayerKey;
        public int Kind; // 0 = v4 CIDR, 1 = v6 ULA, 2 = Interface LUID
    }

    public static class WfpManager
    {
        public static FilterSpec[] GetAllFilterSpecs()
        {
            return new FilterSpec[]
            {
                new FilterSpec { Key = WfpConst.FILTER_V4_CIDR_CONNECT,  Name = "Tailscale IPv4 100.64.0.0/10 (ALE Connect)",       LayerKey = WfpConst.LAYER_ALE_AUTH_CONNECT_V4,     Kind = 0 },
                new FilterSpec { Key = WfpConst.FILTER_V4_CIDR_RECV,     Name = "Tailscale IPv4 100.64.0.0/10 (ALE Recv/Accept)",   LayerKey = WfpConst.LAYER_ALE_AUTH_RECV_ACCEPT_V4, Kind = 0 },
                new FilterSpec { Key = WfpConst.FILTER_V4_CIDR_DATAGRAM, Name = "Tailscale IPv4 100.64.0.0/10 (Datagram Data)",     LayerKey = WfpConst.LAYER_DATAGRAM_DATA_V4,        Kind = 0 },

                new FilterSpec { Key = WfpConst.FILTER_V6_CIDR_CONNECT,  Name = "Tailscale IPv6 fd7a:115c:a1e0::/48 (ALE Connect)",     LayerKey = WfpConst.LAYER_ALE_AUTH_CONNECT_V6,     Kind = 1 },
                new FilterSpec { Key = WfpConst.FILTER_V6_CIDR_RECV,     Name = "Tailscale IPv6 fd7a:115c:a1e0::/48 (ALE Recv/Accept)", LayerKey = WfpConst.LAYER_ALE_AUTH_RECV_ACCEPT_V6, Kind = 1 },
                new FilterSpec { Key = WfpConst.FILTER_V6_CIDR_DATAGRAM, Name = "Tailscale IPv6 fd7a:115c:a1e0::/48 (Datagram Data)",   LayerKey = WfpConst.LAYER_DATAGRAM_DATA_V6,        Kind = 1 },

                new FilterSpec { Key = WfpConst.FILTER_V4_IF_CONNECT,    Name = "Tailscale Adapter LUID v4 (ALE Connect)",          LayerKey = WfpConst.LAYER_ALE_AUTH_CONNECT_V4,     Kind = 2 },
                new FilterSpec { Key = WfpConst.FILTER_V4_IF_RECV,       Name = "Tailscale Adapter LUID v4 (ALE Recv/Accept)",      LayerKey = WfpConst.LAYER_ALE_AUTH_RECV_ACCEPT_V4, Kind = 2 },
                new FilterSpec { Key = WfpConst.FILTER_V4_IF_DATAGRAM,   Name = "Tailscale Adapter LUID v4 (Datagram Data)",        LayerKey = WfpConst.LAYER_DATAGRAM_DATA_V4,        Kind = 2 },

                new FilterSpec { Key = WfpConst.FILTER_V6_IF_CONNECT,    Name = "Tailscale Adapter LUID v6 (ALE Connect)",          LayerKey = WfpConst.LAYER_ALE_AUTH_CONNECT_V6,     Kind = 2 },
                new FilterSpec { Key = WfpConst.FILTER_V6_IF_RECV,       Name = "Tailscale Adapter LUID v6 (ALE Recv/Accept)",      LayerKey = WfpConst.LAYER_ALE_AUTH_RECV_ACCEPT_V6, Kind = 2 },
                new FilterSpec { Key = WfpConst.FILTER_V6_IF_DATAGRAM,   Name = "Tailscale Adapter LUID v6 (Datagram Data)",        LayerKey = WfpConst.LAYER_DATAGRAM_DATA_V6,        Kind = 2 }
            };
        }

        private static void CheckResult(uint code, string operation)
        {
            if (code != 0u)
            {
                throw new InvalidOperationException(string.Format("{0} failed with WFP error 0x{1:X8} ({1}).", operation, code));
            }
        }

        private static uint DeleteKnownFilters(IntPtr engine)
        {
            uint deleted = 0u;
            FilterSpec[] specs = GetAllFilterSpecs();
            for (int i = 0; i < specs.Length; i++)
            {
                Guid key = specs[i].Key;
                uint rc = NativeMethods.FwpmFilterDeleteByKey0(engine, ref key);
                if (rc == 0u)
                {
                    deleted++;
                }
                else if (rc != WfpConst.FWP_E_FILTER_NOT_FOUND)
                {
                    CheckResult(rc, "FwpmFilterDeleteByKey0(" + specs[i].Name + ")");
                }
            }
            return deleted;
        }

        public static uint Install(bool includeInterfaceRule, ulong tailscaleInterfaceLuid)
        {
            IntPtr engine = IntPtr.Zero;
            bool inTxn = false;
            List<IntPtr> allocs = new List<IntPtr>();
            uint added = 0u;

            try
            {
                CheckResult(NativeMethods.FwpmEngineOpen0(null, WfpConst.RPC_C_AUTHN_DEFAULT, IntPtr.Zero, IntPtr.Zero, out engine), "FwpmEngineOpen0");
                CheckResult(NativeMethods.FwpmTransactionBegin0(engine, 0u), "FwpmTransactionBegin0");
                inTxn = true;

                // Clean up prior installation cleanly inside transaction
                DeleteKnownFilters(engine);

                Guid subKey = WfpConst.SubLayerKey;
                uint rcSubDel = NativeMethods.FwpmSubLayerDeleteByKey0(engine, ref subKey);
                if (rcSubDel != 0u && rcSubDel != WfpConst.FWP_E_SUBLAYER_NOT_FOUND)
                {
                    CheckResult(rcSubDel, "FwpmSubLayerDeleteByKey0");
                }

                // Ensure provider exists
                Guid provKey = WfpConst.ProviderKey;
                IntPtr provCheckPtr;
                uint rcProvGet = NativeMethods.FwpmProviderGetByKey0(engine, ref provKey, out provCheckPtr);
                if (rcProvGet == 0u)
                {
                    NativeMethods.FwpmFreeMemory0(ref provCheckPtr);
                }
                else if (rcProvGet == WfpConst.FWP_E_PROVIDER_NOT_FOUND)
                {
                    IntPtr pName = Marshal.StringToHGlobalUni("Tailscale + NordVPN Coexistence Provider");
                    IntPtr pDesc = Marshal.StringToHGlobalUni("Persistent Hard-Permit provider so Tailscale peers and MagicDNS bypass NDivert LeakBlock.");
                    allocs.Add(pName);
                    allocs.Add(pDesc);

                    FWPM_PROVIDER0 prov = new FWPM_PROVIDER0();
                    prov.providerKey = WfpConst.ProviderKey;
                    prov.displayData.name = pName;
                    prov.displayData.description = pDesc;
                    prov.flags = WfpConst.FWPM_PROVIDER_FLAG_PERSISTENT;
                    CheckResult(NativeMethods.FwpmProviderAdd0(engine, ref prov, IntPtr.Zero), "FwpmProviderAdd0");
                }
                else
                {
                    CheckResult(rcProvGet, "FwpmProviderGetByKey0");
                }

                // Allocate shared providerKey unmanaged copy
                IntPtr pProvKey = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
                allocs.Add(pProvKey);
                Marshal.StructureToPtr(WfpConst.ProviderKey, pProvKey, false);

                // Create high-weight sublayer (0xFFFF = 65535 > NordVPN sublayer 34212)
                IntPtr sName = Marshal.StringToHGlobalUni("Tailscale + NordVPN Coexistence Sublayer");
                IntPtr sDesc = Marshal.StringToHGlobalUni("Weight 0xFFFF sublayer evaluating Tailscale Hard-Permit rules before NordVPN split tunnel sublayer (34212).");
                allocs.Add(sName);
                allocs.Add(sDesc);

                FWPM_SUBLAYER0 subLayer = new FWPM_SUBLAYER0();
                subLayer.subLayerKey = WfpConst.SubLayerKey;
                subLayer.displayData.name = sName;
                subLayer.displayData.description = sDesc;
                subLayer.flags = WfpConst.FWPM_SUBLAYER_FLAG_PERSISTENT;
                subLayer.providerKey = pProvKey;
                subLayer.weight = 0xFFFF;
                CheckResult(NativeMethods.FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero), "FwpmSubLayerAdd0");

                // Prepare shared condition payload buffers:
                // 1) IPv4 100.64.0.0/10 in host byte order: 0x64400000 / 0xFFC00000
                IntPtr pV4AddrMask = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWP_V4_ADDR_AND_MASK)));
                allocs.Add(pV4AddrMask);
                FWP_V4_ADDR_AND_MASK v4Mask = new FWP_V4_ADDR_AND_MASK();
                v4Mask.addr = (100u << 24) | (64u << 16);
                v4Mask.mask = 0xFFC00000u;
                Marshal.StructureToPtr(v4Mask, pV4AddrMask, false);

                // 2) IPv6 fd7a:115c:a1e0::/48 in network byte order
                byte[] v6Bytes = IPAddress.Parse("fd7a:115c:a1e0::").GetAddressBytes();
                IntPtr pV6AddrMask = Marshal.AllocHGlobal(17);
                allocs.Add(pV6AddrMask);
                Marshal.Copy(v6Bytes, 0, pV6AddrMask, 16);
                Marshal.WriteByte(pV6AddrMask, 16, 48);

                // 3) Tailscale Interface LUID pointer (UINT64*)
                IntPtr pIfLuid = IntPtr.Zero;
                if (includeInterfaceRule && tailscaleInterfaceLuid != 0UL)
                {
                    pIfLuid = Marshal.AllocHGlobal(sizeof(ulong));
                    allocs.Add(pIfLuid);
                    Marshal.WriteInt64(pIfLuid, unchecked((long)tailscaleInterfaceLuid));
                }

                FilterSpec[] specs = GetAllFilterSpecs();
                for (int i = 0; i < specs.Length; i++)
                {
                    FilterSpec spec = specs[i];
                    if (spec.Kind == 2 && pIfLuid == IntPtr.Zero)
                    {
                        continue;
                    }

                    FWPM_FILTER_CONDITION0 cond = new FWPM_FILTER_CONDITION0();
                    if (spec.Kind == 0)
                    {
                        cond.fieldKey = WfpConst.CONDITION_IP_REMOTE_ADDRESS;
                        cond.matchType = WfpConst.FWP_MATCH_EQUAL;
                        cond.conditionValue.type = WfpConst.FWP_V4_ADDR_MASK;
                        cond.conditionValue.val.ptr = pV4AddrMask;
                    }
                    else if (spec.Kind == 1)
                    {
                        cond.fieldKey = WfpConst.CONDITION_IP_REMOTE_ADDRESS;
                        cond.matchType = WfpConst.FWP_MATCH_EQUAL;
                        cond.conditionValue.type = WfpConst.FWP_V6_ADDR_MASK;
                        cond.conditionValue.val.ptr = pV6AddrMask;
                    }
                    else
                    {
                        cond.fieldKey = WfpConst.CONDITION_IP_LOCAL_INTERFACE;
                        cond.matchType = WfpConst.FWP_MATCH_EQUAL;
                        cond.conditionValue.type = WfpConst.FWP_UINT64;
                        cond.conditionValue.val.ptr = pIfLuid;
                    }

                    IntPtr pCond = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0)));
                    allocs.Add(pCond);
                    Marshal.StructureToPtr(cond, pCond, false);

                    IntPtr fName = Marshal.StringToHGlobalUni(spec.Name);
                    IntPtr fDesc = Marshal.StringToHGlobalUni("Hard-Permit (CLEAR_ACTION_RIGHT) for Tailscale coexistence with NordVPN NDivert.");
                    allocs.Add(fName);
                    allocs.Add(fDesc);

                    FWPM_FILTER0 filter = new FWPM_FILTER0();
                    filter.filterKey = spec.Key;
                    filter.displayData.name = fName;
                    filter.displayData.description = fDesc;
                    filter.flags = WfpConst.FWPM_FILTER_FLAG_PERSISTENT | WfpConst.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
                    filter.providerKey = pProvKey;
                    filter.layerKey = spec.LayerKey;
                    filter.subLayerKey = WfpConst.SubLayerKey;
                    filter.weight.type = WfpConst.FWP_UINT8;
                    filter.weight.val.uint8 = 15;
                    filter.numFilterConditions = 1u;
                    filter.filterCondition = pCond;
                    filter.action.type = WfpConst.FWP_ACTION_PERMIT;
                    filter.action.filterType = Guid.Empty;

                    ulong filterId;
                    CheckResult(NativeMethods.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out filterId), "FwpmFilterAdd0(" + spec.Name + ")");
                    added++;
                }

                CheckResult(NativeMethods.FwpmTransactionCommit0(engine), "FwpmTransactionCommit0");
                inTxn = false;
                return added;
            }
            catch
            {
                if (inTxn && engine != IntPtr.Zero)
                {
                    NativeMethods.FwpmTransactionAbort0(engine);
                }
                throw;
            }
            finally
            {
                for (int i = 0; i < allocs.Count; i++)
                {
                    if (allocs[i] != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(allocs[i]);
                    }
                }
                if (engine != IntPtr.Zero)
                {
                    NativeMethods.FwpmEngineClose0(engine);
                }
            }
        }

        public static uint Uninstall()
        {
            IntPtr engine = IntPtr.Zero;
            bool inTxn = false;

            try
            {
                CheckResult(NativeMethods.FwpmEngineOpen0(null, WfpConst.RPC_C_AUTHN_DEFAULT, IntPtr.Zero, IntPtr.Zero, out engine), "FwpmEngineOpen0");
                CheckResult(NativeMethods.FwpmTransactionBegin0(engine, 0u), "FwpmTransactionBegin0");
                inTxn = true;

                uint deleted = DeleteKnownFilters(engine);

                Guid subKey = WfpConst.SubLayerKey;
                uint rcSub = NativeMethods.FwpmSubLayerDeleteByKey0(engine, ref subKey);
                if (rcSub != 0u && rcSub != WfpConst.FWP_E_SUBLAYER_NOT_FOUND)
                {
                    CheckResult(rcSub, "FwpmSubLayerDeleteByKey0");
                }

                Guid provKey = WfpConst.ProviderKey;
                uint rcProv = NativeMethods.FwpmProviderDeleteByKey0(engine, ref provKey);
                if (rcProv != 0u && rcProv != WfpConst.FWP_E_PROVIDER_NOT_FOUND)
                {
                    CheckResult(rcProv, "FwpmProviderDeleteByKey0");
                }

                CheckResult(NativeMethods.FwpmTransactionCommit0(engine), "FwpmTransactionCommit0");
                inTxn = false;
                return deleted;
            }
            catch
            {
                if (inTxn && engine != IntPtr.Zero)
                {
                    NativeMethods.FwpmTransactionAbort0(engine);
                }
                throw;
            }
            finally
            {
                if (engine != IntPtr.Zero)
                {
                    NativeMethods.FwpmEngineClose0(engine);
                }
            }
        }

        public static string[] QueryStatus()
        {
            List<string> lines = new List<string>();
            IntPtr engine = IntPtr.Zero;
            try
            {
                uint rcOpen = NativeMethods.FwpmEngineOpen0(null, WfpConst.RPC_C_AUTHN_DEFAULT, IntPtr.Zero, IntPtr.Zero, out engine);
                if (rcOpen == WfpConst.ERROR_ACCESS_DENIED)
                {
                    lines.Add("WFP_ACCESS_DENIED");
                    return lines.ToArray();
                }
                CheckResult(rcOpen, "FwpmEngineOpen0");

                Guid provKey = WfpConst.ProviderKey;
                IntPtr provPtr;
                uint rcProv = NativeMethods.FwpmProviderGetByKey0(engine, ref provKey, out provPtr);
                if (rcProv == 0u)
                {
                    NativeMethods.FwpmFreeMemory0(ref provPtr);
                    lines.Add("Provider: Present");
                }
                else if (rcProv == WfpConst.ERROR_ACCESS_DENIED)
                {
                    lines.Add("WFP_ACCESS_DENIED");
                    return lines.ToArray();
                }
                else
                {
                    lines.Add("Provider: Missing (0x" + rcProv.ToString("X8") + ")");
                }

                Guid subKey = WfpConst.SubLayerKey;
                IntPtr subPtr;
                uint rcSub = NativeMethods.FwpmSubLayerGetByKey0(engine, ref subKey, out subPtr);
                if (rcSub == 0u)
                {
                    FWPM_SUBLAYER0 sl = (FWPM_SUBLAYER0)Marshal.PtrToStructure(subPtr, typeof(FWPM_SUBLAYER0));
                    lines.Add("SubLayer: Present (weight=" + sl.weight + ")");
                    NativeMethods.FwpmFreeMemory0(ref subPtr);
                }
                else
                {
                    lines.Add("SubLayer: Missing (0x" + rcSub.ToString("X8") + ")");
                }

                FilterSpec[] specs = GetAllFilterSpecs();
                for (int i = 0; i < specs.Length; i++)
                {
                    Guid fKey = specs[i].Key;
                    IntPtr fPtr;
                    uint rcF = NativeMethods.FwpmFilterGetByKey0(engine, ref fKey, out fPtr);
                    if (rcF == 0u)
                    {
                        FWPM_FILTER0 flt = (FWPM_FILTER0)Marshal.PtrToStructure(fPtr, typeof(FWPM_FILTER0));
                        lines.Add("Filter [Present] id=" + flt.filterId + " flags=0x" + flt.flags.ToString("X") + " : " + specs[i].Name);
                        NativeMethods.FwpmFreeMemory0(ref fPtr);
                    }
                    else if (rcF == WfpConst.FWP_E_FILTER_NOT_FOUND)
                    {
                        lines.Add("Filter [Missing] : " + specs[i].Name);
                    }
                    else
                    {
                        lines.Add("Filter [Error 0x" + rcF.ToString("X8") + "] : " + specs[i].Name);
                    }
                }
                return lines.ToArray();
            }
            finally
            {
                if (engine != IntPtr.Zero)
                {
                    NativeMethods.FwpmEngineClose0(engine);
                }
            }
        }

        public static string ValidateLayouts()
        {
            if (IntPtr.Size != 8)
            {
                throw new NotSupportedException("Expected 64-bit process for x64 SDK reference validation.");
            }

            AssertLayout(typeof(FWP_V4_ADDR_AND_MASK), 8, new string[] { "addr", "mask" }, new int[] { 0, 4 });
            AssertLayout(typeof(FWP_V6_ADDR_AND_MASK), 17, new string[] { "addr", "prefixLength" }, new int[] { 0, 16 });
            AssertLayout(typeof(FWP_VALUE0), 16, new string[] { "type", "val" }, new int[] { 0, 8 });
            AssertLayout(typeof(FWP_CONDITION_VALUE0), 16, new string[] { "type", "val" }, new int[] { 0, 8 });
            AssertLayout(typeof(FWPM_DISPLAY_DATA0), 16, new string[] { "name", "description" }, new int[] { 0, 8 });
            AssertLayout(typeof(FWP_BYTE_BLOB), 16, new string[] { "size", "data" }, new int[] { 0, 8 });
            AssertLayout(typeof(FWPM_SESSION0), 72, new string[] { "sessionKey", "displayData", "flags", "kernelMode" }, new int[] { 0, 16, 32, 64 });
            AssertLayout(typeof(FWPM_PROVIDER0), 64, new string[] { "providerKey", "flags", "providerData", "serviceName" }, new int[] { 0, 32, 40, 56 });
            AssertLayout(typeof(FWPM_SUBLAYER0), 72, new string[] { "subLayerKey", "flags", "providerKey", "providerData", "weight" }, new int[] { 0, 32, 40, 48, 64 });
            AssertLayout(typeof(FWPM_ACTION0), 20, new string[] { "type", "filterType" }, new int[] { 0, 4 });
            AssertLayout(typeof(FWPM_FILTER_CONDITION0), 40, new string[] { "fieldKey", "matchType", "conditionValue" }, new int[] { 0, 16, 24 });
            AssertLayout(
                typeof(FWPM_FILTER0),
                200,
                new string[] { "filterKey", "flags", "providerKey", "layerKey", "subLayerKey", "weight", "numFilterConditions", "filterCondition", "action", "context", "reserved", "filterId", "effectiveWeight" },
                new int[] { 0, 32, 40, 64, 80, 96, 112, 120, 128, 152, 168, 176, 184 });

            uint v4Addr = (100u << 24) | (64u << 16);
            if (v4Addr != 0x64400000u)
            {
                throw new InvalidOperationException("Unexpected IPv4 CGNAT encoding.");
            }
            byte[] v6 = IPAddress.Parse("fd7a:115c:a1e0::").GetAddressBytes();
            if (v6.Length != 16 || v6[0] != 0xFD || v6[1] != 0x7A || v6[2] != 0x11 || v6[3] != 0x5C || v6[4] != 0xA1 || v6[5] != 0xE0)
            {
                throw new InvalidOperationException("Unexpected IPv6 ULA prefix encoding.");
            }

            return "ALL_12_STRUCT_LAYOUTS_AND_CIDR_ENCODINGS_VERIFIED";
        }

        private static void AssertLayout(Type t, int expectedSize, string[] fields, int[] expectedOffsets)
        {
            int actualSize = Marshal.SizeOf(t);
            if (actualSize != expectedSize)
            {
                throw new InvalidOperationException(string.Format("Size mismatch on {0}: expected {1}, got {2}", t.Name, expectedSize, actualSize));
            }
            for (int i = 0; i < fields.Length; i++)
            {
                int actualOffset = Marshal.OffsetOf(t, fields[i]).ToInt32();
                if (actualOffset != expectedOffsets[i])
                {
                    throw new InvalidOperationException(string.Format("Offset mismatch on {0}.{1}: expected {2}, got {3}", t.Name, fields[i], expectedOffsets[i], actualOffset));
                }
            }
        }
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'TailscaleNordVpnWfp.WfpManager').Type) {
    Add-Type -TypeDefinition $CSharpSource -Language CSharp
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TailscaleAdapter {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceDescription -like 'Tailscale Tunnel*' -or $_.Name -eq 'Tailscale'
    })
    if ($adapters.Count -gt 0) {
        return $adapters[0]
    }
    return $null
}

switch ($Action) {
    'Validate' {
        $res = [TailscaleNordVpnWfp.WfpManager]::ValidateLayouts()
        Write-Host "[PASS] $res" -ForegroundColor Green
        $ts = Get-TailscaleAdapter
        if ($ts) {
            Write-Host ("[INFO] Detected Tailscale adapter: Name='{0}', Desc='{1}', ifIndex={2}, NetLuid={3} (0x{4:X16})" -f `
                $ts.Name, $ts.InterfaceDescription, $ts.ifIndex, [uint64]$ts.NetLuid, [uint64]$ts.NetLuid)
        }
        else {
            Write-Host "[INFO] Tailscale adapter not currently present."
        }
    }

    'Status' {
        Write-Host "=== Tailscale & NordLynx Adapters ===" -ForegroundColor Cyan
        $relevant = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like '*Tailscale*' -or $_.InterfaceDescription -like 'Tailscale*' -or $_.Name -like '*Nord*'
        })
        foreach ($adp in $relevant) {
            $v6Bind = Get-NetAdapterBinding -Name $adp.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $v6State = if ($v6Bind) { $v6Bind.Enabled } else { 'Unknown' }
            Write-Host ("  Adapter='{0}' ifIndex={1} Status={2} ms_tcpip6={3} NetLuid=0x{4:X16}" -f `
                $adp.Name, $adp.ifIndex, $adp.Status, $v6State, [uint64]$adp.NetLuid)
        }

        Write-Host "`n=== Tailscale + NordVPN WFP Coexistence Filters ===" -ForegroundColor Cyan
        $statusLines = [TailscaleNordVpnWfp.WfpManager]::QueryStatus()
        if ($statusLines.Count -eq 1 -and $statusLines[0] -eq 'WFP_ACCESS_DENIED') {
            Write-Warning "Access denied querying BFE/WFP objects. Re-run in an elevated Administrator PowerShell to inspect WFP filter state."
        }
        else {
            foreach ($line in $statusLines) {
                Write-Host "  $line"
            }
        }
    }

    'RestoreIpv6' {
        if (-not (Test-IsAdministrator)) {
            throw "Action 'RestoreIpv6' requires an elevated Administrator PowerShell."
        }
        $ts = Get-TailscaleAdapter
        if (-not $ts) {
            throw "Tailscale adapter not found. Ensure Tailscale is installed/running."
        }
        Enable-NetAdapterBinding -Name $ts.Name -ComponentID ms_tcpip6 -ErrorAction Stop
        $v6Bind = Get-NetAdapterBinding -Name $ts.Name -ComponentID ms_tcpip6
        Write-Host ("[OK] ms_tcpip6 on '{0}' is now Enabled={1}" -f $ts.Name, $v6Bind.Enabled) -ForegroundColor Green
    }

    'Install' {
        if (-not (Test-IsAdministrator)) {
            throw "Action 'Install' requires an elevated Administrator PowerShell."
        }
        [void][TailscaleNordVpnWfp.WfpManager]::ValidateLayouts()

        $ts = Get-TailscaleAdapter
        $tsLuid = [uint64]0
        if ($ts) {
            $tsLuid = [uint64]$ts.NetLuid
            Write-Host ("[INFO] Found Tailscale adapter '{0}' (ifIndex={1}, NetLuid=0x{2:X16})" -f $ts.Name, $ts.ifIndex, $tsLuid)
        }
        else {
            Write-Warning "Tailscale adapter not found right now. Installing CIDR filters (100.64.0.0/10 and fd7a:115c:a1e0::/48) without Interface LUID filters."
        }

        $count = [TailscaleNordVpnWfp.WfpManager]::Install($IncludeInterfaceRule, $tsLuid)
        Write-Host ("[OK] Installed {0} persistent WFP Hard-Permit filters in sublayer weight 0xFFFF." -f $count) -ForegroundColor Green

        if ($RestoreIpv6 -and $ts) {
            Enable-NetAdapterBinding -Name $ts.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            Write-Host ("[OK] Re-enabled ms_tcpip6 on '{0}' (Tailscale IPv6 / IPv6 MagicDNS)." -f $ts.Name) -ForegroundColor Green
            Write-Host "[NOTE] NordVPN's Ipv6LeakBlocker disables ms_tcpip6 again whenever NordVPN reconnects. If you need IPv6 over Tailscale after a reconnect, run '-Action RestoreIpv6' (IPv4 + MagicDNS 100.100.100.100 remains permanently working)." -ForegroundColor Yellow
        }
    }

    'Uninstall' {
        if (-not (Test-IsAdministrator)) {
            throw "Action 'Uninstall' requires an elevated Administrator PowerShell."
        }
        $deleted = [TailscaleNordVpnWfp.WfpManager]::Uninstall()
        Write-Host ("[OK] Removed {0} WFP Hard-Permit filters, sublayer, and provider." -f $deleted) -ForegroundColor Green
    }
}
