## SAFE.AuthClient

[![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/SAFE.AuthClient.svg)](https://www.nuget.org/packages/SAFE.AuthClient)

Auth client for SAFENetwork (Safe Access For Everyone) - a decentralized, secure and anonymous data storage network.

## How to use it

- Reference MaidSafe.SafeApp (0.2.1) NuGet pkg.
- Add crust.config and log.toml to your app exe path.
(You can find these files in the solution folder of this repository.)

The crust.config file is currently connecting to Alpha-2 network, which is a test network maintained by MaidSafe.
This test network has a temporary spam-prevention mechanism, which requires some activity 
on SAFENetwork Forum before you can get an invitation to use when creating an account with SAFE.AuthClient.

You can read about how to get the invitation here: https://invite.maidsafe.net/

Creating a session for interacting with the network

    static async Task Main()
    {
        var credentials = new Credentials("some string", "some other string");
        var config = new AuthSessionConfig(credentials);

        using (var client = await AuthClient.InitSessionAsync(config))
        {
            var session = await client.CreateAppSessionAsync(GetAuthReq());
            var app = new SomeApp(session);
            await app.RunAsync();
        }
    }

See more in AuthClientExample.cs file, in Examples folder of the solution.

## Further Help

Get your developer related questions clarified on the [SAFE Dev Forum](https://forum.safedev.org/). If you're looking to share any other ideas or thoughts on the SAFE Network you can reach out on the [SAFE Network Forum](https://safenetforum.org/).


## Contribution

Copyrights are retained by their contributors. No copyright assignment is required to contribute to this project.


## License

This library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

The SAFE.AuthClient is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the BSD-3 / MIT Licenses for more details.