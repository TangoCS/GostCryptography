﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace GostCryptography.Tests.Properties {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "15.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("GostCryptography.Tests.Properties.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot; ?&gt;
        ///&lt;MyXml&gt;
        ///	&lt;SomeElement Encrypt=&quot;false&quot;&gt;
        ///		Here is public data.
        ///	&lt;/SomeElement&gt;
        ///	&lt;SomeElement Encrypt=&quot;true&quot;&gt;
        ///		Here is private data.
        ///	&lt;/SomeElement&gt;
        ///	&lt;SomeElement Encrypt=&quot;true&quot;&gt;
        ///		Here is private data.
        ///	&lt;/SomeElement&gt;
        ///	&lt;SomeElement Encrypt=&quot;true&quot;&gt;
        ///		Here is private data.
        ///	&lt;/SomeElement&gt;
        ///&lt;/MyXml&gt;.
        /// </summary>
        internal static string EncryptedXmlExample {
            get {
                return ResourceManager.GetString("EncryptedXmlExample", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot; ?&gt;
        ///&lt;MyXml&gt;
        ///	&lt;SomeElement Id=&quot;Id1&quot;&gt;
        ///		Here is some data to sign.
        ///	&lt;/SomeElement&gt;
        ///&lt;/MyXml&gt;.
        /// </summary>
        internal static string SignedXmlExample {
            get {
                return ResourceManager.GetString("SignedXmlExample", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot; standalone=&quot;no&quot;?&gt;
        ///&lt;S:Envelope xmlns:S=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot;
        ///			xmlns:wsse=&quot;http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd&quot;
        ///			xmlns:wsu=&quot;http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd&quot;
        ///			&gt;
        ///	&lt;S:Header&gt;
        ///		&lt;wsse:Security S:actor=&quot;http://smev.gosuslugi.ru/actors/smev&quot;&gt;
        ///			&lt;ds:Signature xmlns:ds=&quot;http://www.w3.org/2000/09/xmldsig#&quot;&gt;
        ///				&lt;ds:KeyInfo&gt;
        ///					&lt;wsse:SecurityTokenReference&gt; [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string SmevExample {
            get {
                return ResourceManager.GetString("SmevExample", resourceCulture);
            }
        }
    }
}