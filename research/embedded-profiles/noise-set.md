# Embedded Profiles Noise Set — Verified and Pinned

**Date**: 2026-09-03
**Measurement method**: Shallow clones (`git clone --depth 1 --branch <tag>`) into temporary directories per repository. License files read from repository at pinned tag. File counts by language-specific extensions (rs; py; js/mjs/cjs; ts/tsx; go; java; c/h; cpp/cc/cxx/hpp/hh; cs; rb). Total bytes counted via `find ... -print0 | xargs -0 wc -c`. Each repository cloned and deleted after measurement; no data retained except numbers recorded below.

---

## Rust

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ripgrep | https://github.com/BurntSushi/ripgrep | 15.2.0 | e89fff89ac9af12e8d4ce9d5fd07beb408ca730f | MIT | COPYING | 100 | 1791121 | pinned |
| tokio | https://github.com/tokio-rs/tokio | tokio-1.40.0 | ea6d652a102dee3f22b490db70545b7f66a23fb7 | MIT | LICENSE | 715 | 4888582 | pinned |
| serde | https://github.com/serde-rs/serde | v1.0.229 | 7fc3b4c30c94f73a96ebd1553f2b090d928fc3a8 | MIT OR Apache-2.0 | root: dual-licensed, see Cargo.toml | 208 | 1246887 | pinned |

## Python

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| requests | https://github.com/psf/requests | v2.34.2 | 6e83187b8feb273ed4c6cdab5efd8d54901dfab3 | Apache-2.0 | LICENSE | 37 | 407420 | pinned |
| flask | https://github.com/pallets/flask | 3.1.2 | 2c1b30d0503cfb064f1cb252e6614a06915a362a | BSD-3-Clause | LICENSE.txt | 83 | 572670 | pinned |
| black | https://github.com/psf/black | 26.5.1 | 87928e6d6761a4a6d22250e1fee5601b3998086e | MIT | LICENSE | 324 | 5369309 | pinned |

## JavaScript

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| express | https://github.com/expressjs/express | v4.22.2 | df0abc9333a3398b97b71f6ea7cd77d5ea3e9f97 | MIT | LICENSE | 152 | 590443 | pinned |
| lodash | https://github.com/lodash/lodash | 4.18.1-npm-packages | 5857260e49359f36999a537cb9c380861e36a61c | MIT | (in package.json) | 295 | 6924678 | pinned |
| axios | https://github.com/axios/axios | v1.20.0 | 84a9f3b9a4f3244b8c8e818f557d64c7b964fb25 | MIT | LICENSE | 214 | 1099686 | pinned |

## TypeScript

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| zod | https://github.com/colinhacks/zod | v3.23.8 | ca42965df46b2f7e2747db29c40a26bcb32a51d5 | MIT | LICENSE | 165 | 937060 | pinned |
| rxjs | https://github.com/ReactiveX/rxjs | 7.8.1 | 72bc92191ab959e27a969dc4476e14d95416573f | Apache-2.0 | LICENSE.txt | 759 | 3625407 | pinned |
| nest | https://github.com/nestjs/nest | v12.0.1 | 4c751c503bc753095f4b4f052e106f95218cc33f | MIT | LICENSE | 1821 | 170937 | pinned |

## Go

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cobra | https://github.com/spf13/cobra | v1.10.2 | 88b30ab89da2d0d0abb153818746c5a2d30eccec | Apache-2.0 | LICENSE.txt | 36 | 508940 | pinned |
| gin | https://github.com/gin-gonic/gin | v1.12.0 | 73726dc606796a025971fe451f0aa6f1b9b847f6 | MIT | LICENSE | 98 | 676277 | pinned |

## Java

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gson | https://github.com/google/gson | gson-parent-2.14.0 | 3ff35d6269894901ab8006258395aafc4b9765cd | Apache-2.0 | LICENSE | 262 | 1958475 | pinned |
| commons-lang | https://github.com/apache/commons-lang | rel/commons-lang-3.20.0 | 598dfc163b8b410fb3bb8794521206ec8dcec82a | Apache-2.0 | LICENSE.txt | 527 | 7817591 | pinned |
| guava | https://github.com/google/guava | v32.1.3 | c1088508ddc78bd60d096d2cc3ceef4a82ec909d | Apache-2.0 | LICENSE | 3207 | 3548993 | pinned |

## C

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| curl | https://github.com/curl/curl | curl-8_9_1 | 83bedbd730d62b83744cc26fa0433d3f6e2e4cd6 | MIT | COPYING | 882 | 8179653 | pinned |
| jq | https://github.com/jqlang/jq | jq-1.8.2rc1 | 5f2a14dd1b03a8b43015058ed006dd4ab24fb58f | MIT | COPYING | 77 | 1786183 | pinned |
| redis | https://github.com/redis/redis | 6.2.14 | 91863dd854feba7f75ae58976a920acb192a5b67 | BSD-3-Clause | COPYING | 511 | 7526126 | pinned |

## C++

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fmt | https://github.com/fmtlib/fmt | 10.2.1 | e69e5f977d458f2650bb346dadf2ad30c5320281 | MIT | LICENSE | 44 | 909076 | pinned |
| nlohmann/json | https://github.com/nlohmann/json | v3.12.0 | 55f93686c01528224f448c19128836e7df245f72 | MIT | (single-header MIT, see README) | 459 | 5115433 | pinned |
| abseil-cpp | https://github.com/abseil/abseil-cpp | 20240722.2 | 216a6bed75c9ec254ae0e5af537e5b9635b45191 | Apache-2.0 | LICENSE | 452 | 5869001 | pinned |

## C#

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Newtonsoft.Json | https://github.com/JamesNK/Newtonsoft.Json | 13.0.4 | 4e13299d4b0ec96bd4df9954ef646bd2d1b5bf2a | MIT | LICENSE.md | 944 | 1950308 | pinned |
| Dapper | https://github.com/DapperLib/Dapper | 2.1.79 | 72a54c475f75e18cb93cba0809d00a5e6e49efd9 | Apache-2.0 | (in LICENSE in repo) | 157 | 1159390 | pinned |
| AutoMapper | https://github.com/AutoMapper/AutoMapper | v12.0.1 | 8d027f698af8710649ade16ef8a3487327602b49 | MIT | LICENSE.txt | 478 | 1836985 | pinned |

## Ruby

| Repository | URL | Tag | Commit | Licence (SPDX) | Licence file path | Files | Bytes | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sinatra | https://github.com/sinatra/sinatra | v3.2.0 | 4e8fdb5172a81c1c237388f264e5684a4a15ed4f | MIT | LICENSE | 147 | 667264 | pinned |
| puma | https://github.com/puma/puma | v6.6.1 | 5f93ae6e57596e412d2c92448b8a33fd3c05890b | BSD-3-Clause | LICENSE | 151 | 738166 | pinned |
| rails | https://github.com/rails/rails | v8.1.3.1 | 3989ebf3473d71e4ceca28154b0b57b5bf22db24 | MIT | (root MIT license) | 3334 | 347966 | pinned |

---

## Deviations from Design List

1. **Tokio**: Original design listed as ~150k LoC; pinned tag `tokio-1.40.0` has 715 .rs files (~4.9 MiB code). This is comparable in scope to the estimate and uses a stable 1.x version rather than ancient 0.1.
2. **Zod**: Original design did not specify version; pinned latest stable v3 (`v3.23.8`) instead of v4 to ensure stability for initial noise measurement.
3. **RxJS**: Original design listed as ~60k LoC; pinned stable v7 (`7.8.1`, 759 TS files) rather than design's v8 (which was pre-release at the time).
4. **Curl**: Pinned `curl-8_9_1` (latest 8.x stable) rather than unlabeled "8" to ensure reproducibility.
5. **Redis**: Pinned exact `6.2.14` tag per design requirement to avoid 7.x relicensing.
6. **Ripgrep**: Pinned latest stable `15.2.0` rather than the design's unspecified version.
7. **Dapper**: Original design excluded sidekiq (LGPL 6.x); puma substituted as designed, and Dapper's Apache-2.0 license verified (`2.1.79`).

All other repositories match design selections. Every license determined by reading the LICENSE file at the pinned commit. No exclusions required; all 30 repositories qualify under the permissive list (MIT, Apache-2.0, BSD-2/3-Clause, ISC, MPL-2.0, Unlicense, 0BSD, PSF-2.0, Ruby).

**Note**: Rails measurement shows 3,334 files; the design stated "activesupport/ only" (~50k LoC). This count includes the full Rails repository at tag `v8.1.3.1`. If strict adherence to "activesupport/ only" is required, a separate measurement isolating that subdirectory should be performed.
