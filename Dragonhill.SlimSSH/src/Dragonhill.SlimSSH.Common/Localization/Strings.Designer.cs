﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Dragonhill.SlimSSH.Localization {
    using System;
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Strings {
        
        private static System.Resources.ResourceManager resourceMan;
        
        private static System.Globalization.CultureInfo resourceCulture;
        
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Strings() {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static System.Resources.ResourceManager ResourceManager {
            get {
                if (object.Equals(null, resourceMan)) {
                    System.Resources.ResourceManager temp = new System.Resources.ResourceManager("Dragonhill.SlimSSH.Localization.Strings", typeof(Strings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        internal static string ProtocolVersionExchange_LineTooLong {
            get {
                return ResourceManager.GetString("ProtocolVersionExchange_LineTooLong", resourceCulture);
            }
        }
        
        internal static string ProtocolVersionExchange_LineInvalid {
            get {
                return ResourceManager.GetString("ProtocolVersionExchange_LineInvalid", resourceCulture);
            }
        }
        
        internal static string ProtocolVersionExchange_InvalidVersion {
            get {
                return ResourceManager.GetString("ProtocolVersionExchange_InvalidVersion", resourceCulture);
            }
        }
        
        internal static string ProtocolVersionExchange_InvalidSoftwareVersion {
            get {
                return ResourceManager.GetString("ProtocolVersionExchange_InvalidSoftwareVersion", resourceCulture);
            }
        }
    }
}
