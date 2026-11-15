export namespace bootstrap {

	export class Volume {
	    UUID: string;
	    Label: string;
	    Free: number;
	    Share: string;
	    MediaID: string;

	    static createFrom(source: any = {}) {
	        return new Volume(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.UUID = source["UUID"];
	        this.Label = source["Label"];
	        this.Free = source["Free"];
	        this.Share = source["Share"];
	        this.MediaID = source["MediaID"];
	    }
	}
	export class Plan {
	    ID: string;
	    Model: string;
	    Hardware: string;
	    Arch: string;
	    Volume: Volume;
	    Archive: string;
	    URL: string;
	    SHA256: string;
	    Size: number;
	    Commands: string[];
	    IntegritySource: string;

	    static createFrom(source: any = {}) {
	        return new Plan(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Model = source["Model"];
	        this.Hardware = source["Hardware"];
	        this.Arch = source["Arch"];
	        this.Volume = this.convertValues(source["Volume"], Volume);
	        this.Archive = source["Archive"];
	        this.URL = source["URL"];
	        this.SHA256 = source["SHA256"];
	        this.Size = source["Size"];
	        this.Commands = source["Commands"];
	        this.IntegritySource = source["IntegritySource"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace config {

	export class Conflict {
	    Path: string;
	    Reason: string;
	    NecessaryAddition: string;

	    static createFrom(source: any = {}) {
	        return new Conflict(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Path = source["Path"];
	        this.Reason = source["Reason"];
	        this.NecessaryAddition = source["NecessaryAddition"];
	    }
	}
	export class FilePreview {
	    Path: string;
	    Action: string;
	    Preview: string;

	    static createFrom(source: any = {}) {
	        return new FilePreview(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Path = source["Path"];
	        this.Action = source["Action"];
	        this.Preview = source["Preview"];
	    }
	}

}

export namespace install {

	export class FileChange {
	    Path: string;
	    Action: string;
	    Mode: string;

	    static createFrom(source: any = {}) {
	        return new FileChange(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Path = source["Path"];
	        this.Action = source["Action"];
	        this.Mode = source["Mode"];
	    }
	}
	export class Step {
	    ID: string;
	    Description: string;

	    static createFrom(source: any = {}) {
	        return new Step(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Description = source["Description"];
	    }
	}

}

export namespace main {

	export class ArtifactView {
	    Component: string;
	    Version: string;

	    static createFrom(source: any = {}) {
	        return new ArtifactView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Component = source["Component"];
	        this.Version = source["Version"];
	    }
	}
	export class HostKeyView {
	    Kind: string;
	    Address: string;
	    Fingerprint: string;
	    Expected: string;
	    Algorithm: string;

	    static createFrom(source: any = {}) {
	        return new HostKeyView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Kind = source["Kind"];
	        this.Address = source["Address"];
	        this.Fingerprint = source["Fingerprint"];
	        this.Expected = source["Expected"];
	        this.Algorithm = source["Algorithm"];
	    }
	}
	export class BootstrapDiscovery {
	    Model: string;
	    Hardware: string;
	    Arch: string;
	    Volumes: bootstrap.Volume[];
	    HostKey?: HostKeyView;

	    static createFrom(source: any = {}) {
	        return new BootstrapDiscovery(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Model = source["Model"];
	        this.Hardware = source["Hardware"];
	        this.Arch = source["Arch"];
	        this.Volumes = this.convertValues(source["Volumes"], bootstrap.Volume);
	        this.HostKey = this.convertValues(source["HostKey"], HostKeyView);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConnectionRequest {
	    Host: string;
	    Port: number;
	    User: string;
	    Password: string;

	    static createFrom(source: any = {}) {
	        return new ConnectionRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Host = source["Host"];
	        this.Port = source["Port"];
	        this.User = source["User"];
	        this.Password = source["Password"];
	    }
	}

	export class InspectionView {
	    ID: string;
	    Arch: string;
	    Entware: boolean;
	    Available: number;
	    ActiveCore: string;
	    Versions: Record<string, string>;
	    HostKey?: HostKeyView;

	    static createFrom(source: any = {}) {
	        return new InspectionView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Arch = source["Arch"];
	        this.Entware = source["Entware"];
	        this.Available = source["Available"];
	        this.ActiveCore = source["ActiveCore"];
	        this.Versions = source["Versions"];
	        this.HostKey = this.convertValues(source["HostKey"], HostKeyView);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PlanRequest {
	    InspectionID: string;
	    Cores: string[];
	    ActiveCore: string;
	    UI: boolean;
	    Watchdog: boolean;
	    ImportCore: string;
	    ImportText: string;
	    ProviderURL: string;
	    MihomoProviderURLs: string[];
	    XrayProviderURLs: string[];

	    static createFrom(source: any = {}) {
	        return new PlanRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.InspectionID = source["InspectionID"];
	        this.Cores = source["Cores"];
	        this.ActiveCore = source["ActiveCore"];
	        this.UI = source["UI"];
	        this.Watchdog = source["Watchdog"];
	        this.ImportCore = source["ImportCore"];
	        this.ImportText = source["ImportText"];
	        this.ProviderURL = source["ProviderURL"];
	        this.MihomoProviderURLs = source["MihomoProviderURLs"];
	        this.XrayProviderURLs = source["XrayProviderURLs"];
	    }
	}
	export class PlanView {
	    ID: string;
	    Steps: install.Step[];
	    Changes: install.FileChange[];
	    Artifacts: ArtifactView[];
	    Dependencies: string[];
	    Notes: string[];
	    Files: config.FilePreview[];
	    Conflicts: config.Conflict[];
	    Message: string;

	    static createFrom(source: any = {}) {
	        return new PlanView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Steps = this.convertValues(source["Steps"], install.Step);
	        this.Changes = this.convertValues(source["Changes"], install.FileChange);
	        this.Artifacts = this.convertValues(source["Artifacts"], ArtifactView);
	        this.Dependencies = source["Dependencies"];
	        this.Notes = source["Notes"];
	        this.Files = this.convertValues(source["Files"], config.FilePreview);
	        this.Conflicts = this.convertValues(source["Conflicts"], config.Conflict);
	        this.Message = source["Message"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ResultView {
	    Status: string;
	    Message: string;
	    Backup: string;
	    Completed: string[];
	    Applied: string[];
	    Uncertain: string;
	    Pending: string[];
	    PanelURL: string;
	    Services: verify.ServiceReport[];
	    ReinspectRequired: boolean;

	    static createFrom(source: any = {}) {
	        return new ResultView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Status = source["Status"];
	        this.Message = source["Message"];
	        this.Backup = source["Backup"];
	        this.Completed = source["Completed"];
	        this.Applied = source["Applied"];
	        this.Uncertain = source["Uncertain"];
	        this.Pending = source["Pending"];
	        this.PanelURL = source["PanelURL"];
	        this.Services = this.convertValues(source["Services"], verify.ServiceReport);
	        this.ReinspectRequired = source["ReinspectRequired"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TrustView {
	    ID: string;
	    Description: string;
	    Manual: string;

	    static createFrom(source: any = {}) {
	        return new TrustView(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Description = source["Description"];
	        this.Manual = source["Manual"];
	    }
	}

}

export namespace tls {

	export class TrustResult {
	    Status: string;
	    Detail: string;
	    Code: string;

	    static createFrom(source: any = {}) {
	        return new TrustResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Status = source["Status"];
	        this.Detail = source["Detail"];
	        this.Code = source["Code"];
	    }
	}

}

export namespace verify {

	export class Check {
	    State: string;
	    Detail: string;

	    static createFrom(source: any = {}) {
	        return new Check(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.State = source["State"];
	        this.Detail = source["Detail"];
	    }
	}
	export class ServiceReport {
	    Component: string;
	    Process: Check;
	    Configuration: Check;
	    API: Check;
	    HTTPS: Check;
	    Trust: Check;

	    static createFrom(source: any = {}) {
	        return new ServiceReport(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Component = source["Component"];
	        this.Process = this.convertValues(source["Process"], Check);
	        this.Configuration = this.convertValues(source["Configuration"], Check);
	        this.API = this.convertValues(source["API"], Check);
	        this.HTTPS = this.convertValues(source["HTTPS"], Check);
	        this.Trust = this.convertValues(source["Trust"], Check);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}
