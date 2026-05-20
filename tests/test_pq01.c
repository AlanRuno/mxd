#include "../include/mxd_pq01.h"
#include "../include/mxd_slip10.h"
#include "../include/mxd_bip39.h"
#include "test_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Test 1: PQ-01 master is cryptographically independent from SLIP-10  */
/* Derive both trees from the same BIP-39 seed and assert outputs      */
/* differ — proves the "ml-dsa seed" vs "ed25519 seed" constants       */
/* produce independent trees (the load-bearing security invariant).    */
/* ------------------------------------------------------------------ */
static void test_pq01_master_independent_from_slip10(void) {
  TEST_START("PQ-01 master is independent from SLIP-10 (different master constants)");

  uint8_t seed[64];
  mxd_bip39_seed(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", seed);

  uint8_t mxd02_priv[32], mxd02_chain[32];
  uint8_t pq01_xi[32], pq01_chain[32];

  TEST_ASSERT(mxd_slip10_ed25519_master(seed, mxd02_priv, mxd02_chain) == 0,
              "SLIP-10 master derivation succeeded");
  TEST_ASSERT(mxd_pq01_master(seed, pq01_xi, pq01_chain) == 0,
              "PQ-01 master derivation succeeded");

  TEST_ASSERT(memcmp(mxd02_priv, pq01_xi, 32) != 0,
              "PQ-01 xi differs from SLIP-10 private key (tree independence)");
  TEST_ASSERT(memcmp(mxd02_chain, pq01_chain, 32) != 0,
              "PQ-01 chain differs from SLIP-10 chain code (tree independence)");

  TEST_END("PQ-01 master is independent from SLIP-10 (different master constants)");
}

/* ------------------------------------------------------------------ */
/* Test 2: PQ-01 master is deterministic                               */
/* Two calls with the same seed must produce identical (xi, chain).    */
/* ------------------------------------------------------------------ */
static void test_pq01_master_reproducible(void) {
  TEST_START("PQ-01 master derivation is deterministic");

  uint8_t seed[64];
  mxd_bip39_seed(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", seed);

  uint8_t a[32], ac[32], b[32], bc[32];
  TEST_ASSERT(mxd_pq01_master(seed, a, ac) == 0,
              "First PQ-01 master derivation returned 0");
  TEST_ASSERT(mxd_pq01_master(seed, b, bc) == 0,
              "Second PQ-01 master derivation returned 0");

  TEST_ASSERT(memcmp(a, b, 32) == 0,
              "xi is identical across both calls (deterministic)");
  TEST_ASSERT(memcmp(ac, bc, 32) == 0,
              "chain is identical across both calls (deterministic)");

  TEST_END("PQ-01 master derivation is deterministic");
}

/* ------------------------------------------------------------------ */
/* Test 3: PQ-01 path account separation                               */
/* account=0 vs account=7 must produce different leaf xi values.       */
/* ------------------------------------------------------------------ */
static void test_pq01_path_account_separation(void) {
  TEST_START("PQ-01 path account=0 and account=7 produce distinct leaf xi");

  uint8_t seed[64];
  mxd_bip39_seed(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", seed);

  uint8_t leaf0_xi[32], leaf0_c[32], leaf7_xi[32], leaf7_c[32];
  TEST_ASSERT(mxd_pq01_derive_mxd_path(seed, 19800, 0, leaf0_xi, leaf0_c) == 0,
              "derive_mxd_path account=0 returned 0");
  TEST_ASSERT(mxd_pq01_derive_mxd_path(seed, 19800, 7, leaf7_xi, leaf7_c) == 0,
              "derive_mxd_path account=7 returned 0");

  TEST_ASSERT(memcmp(leaf0_xi, leaf7_xi, 32) != 0,
              "account=0 and account=7 leaf xi values differ");

  TEST_END("PQ-01 path account=0 and account=7 produce distinct leaf xi");
}

/* ------------------------------------------------------------------ */
/* Test 4: PQ-01 KeyGen Deterministic Round Trip                       */
/* Two calls with the same leaf ξ MUST produce byte-identical keys.   */
/* Verifies that mxd_pq01_keygen_at_leaf is deterministic (no         */
/* randombytes consumption) per FIPS 204 §6.1.                         */
/* ------------------------------------------------------------------ */
static void test_pq01_keygen_deterministic_round_trip(void) {
  TEST_START("PQ-01 KeyGen Deterministic Round Trip");

  uint8_t seed[64];
  mxd_bip39_seed("abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon abandon about", "", seed);

  uint8_t leaf_xi[32], leaf_c[32];
  mxd_pq01_derive_mxd_path(seed, 19800, 0, leaf_xi, leaf_c);

  uint8_t pub_a[2592], priv_a[4896], pub_b[2592], priv_b[4896];
  TEST_ASSERT(mxd_pq01_keygen_at_leaf(leaf_xi, pub_a, priv_a) == 0,
              "first keygen succeeds");
  TEST_ASSERT(mxd_pq01_keygen_at_leaf(leaf_xi, pub_b, priv_b) == 0,
              "second keygen succeeds");
  TEST_ASSERT(memcmp(pub_a, pub_b, 2592) == 0,
              "pub bytes deterministic");
  TEST_ASSERT(memcmp(priv_a, priv_b, 4896) == 0,
              "priv bytes deterministic");

  TEST_END("PQ-01 KeyGen Deterministic Round Trip");
}


/* ------------------------------------------------------------------ */
/* Test 5: PQ-01 KeyGen byte-identity vs MXD-PQ-01-test-vectors.json   */
/* Asserts the C-side mxd_pq01_keygen_at_leaf produces the exact       */
/* pub2592 + priv4896 published in the spec vector for the canonical   */
/* abandon_x11_about_no_passphrase_account0 leaf xi. Closes I6-2 from  */
/* AUDIT_2026-05-05_v6.md (test gap on whether pq-crystals C packing   */
/* matches the JSON-published bytes generated by dilithium-py).        */
/* ------------------------------------------------------------------ */
static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) {
  if (strlen(hex) != outlen * 2) return -1;
  for (size_t i = 0; i < outlen; i++) {
    int hi = hex_nibble(hex[i*2]);
    int lo = hex_nibble(hex[i*2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static const char LEAF_XI32_HEX[] =
    "3edfc77beaea52c7ebb640a61f50388d0a903c1c07152617da8f4f12d8aa7d65";

static const char EXPECTED_PUB2592_HEX[] =
    "3de4c5f264b53f8936ccb279d03dbd050832c0a41a196069f54fc8824d1ef4cfc0269185f370e4a85abf1744240a71fe"
    "f3ea2f961db674e3717bcbde88599430dcc70c195e0f09ae580e79b0e40d4b103bae9de903e780f2484a384fc5d60ae3"
    "4d70da6f5137efd346d9ebbc509b49c42e844eaba05cc54db5c9f90155a0c0b29b49d5f3e4c1422b36b93e0f7037385b"
    "99b292b4401d2ef44191e3db759ecbb4a9c593bc157b02bd82d1857113539c8e3e8d078fc72e34655779947cedc397c2"
    "2d6634a6e22b4fdcb27399c8c536466c0289bda26ba67163b765f9ee5e8f1dbec7f8f9b0c1e5ece9f5d5488693f63317"
    "5c7b2cde151ad379333f85747d14786ea0580d13f7aec292a4a4fca55b3dab23948c2d34eda53bba5773a75f153fbf11"
    "1f82cb48a80e148d844bf4e74c17e073edf280f4f383767b08c3fd42031c35036385845a338ba20b3bd351ec499cb386"
    "a6099efe56028446c10006b41b6935383942e050cd45a025ff2da37291870a020667caa4d53f7ee19b0bda2e7a19be7f"
    "d1583aaeecd2dc2b73cf5f38fede33edfde2ca0d0049cdccee87e7917cd9815e9a2ab05ac4b2c9fa406e301b2b8a494e"
    "c85b2e7342eed385e75e9f1d4ef06b73d5193d016d38105ef595f3a89bbfbcb493f724d8ecaf1e457eab59a42f23ad75"
    "c9d23d1ff1b8d2c5ed6403e074aceb9198db5cdd693fb53773f2f454d4db3507bc811426bea6ec7d1bda4461449cde3f"
    "eae3c71cf5f50b77a61a6e0f9232f49910845b4256dc3726c1d1785bddd60cdf53fb38ff13bc2f0ace80674eeba81ca5"
    "3c75d0bb60bf88b6f51e82ab80fe330919da4f8c25e8d07e39dc535266f62a8f16a2ab02ddec83574752a57a394067a8"
    "f182c8d366b0854dae787fad57fd5c3a55f4ebade50951929b042ce49711365a7614de95cf79b9e9a996c8dfc251c29d"
    "fb1b2419dbacde7c611ddac3166ff6ece9609dd55af485a36a8fabdb6b9808436d35e10f7cc11365013a99511a14f35f"
    "44bec65ed0f1f4b8e257d7d607a4bffbd365aaa8922b97750bedce55515ffad4027cdabf87c2f6856815e0e924212837"
    "784ec5345b0f0a41d617cfcd3b1beae1e0fb4eaf0e7393721fd29bfe3c6a6fef8be2049ac9058b791b8d7cf751873625"
    "34aca9a7a43623af03518f339b498824d1a9b09e565fb9bdef12e7778886f15a391c16028059c71ab2fca4e5cfa81d7b"
    "a8aec3f8659aa017137294ba0e005193a6aec216cc596c77f5af1febd27da1d40994c96cebd890d56eccc3e269fd8c79"
    "434f51b855274701e125262673d8f42a18b3bf852aa8135e6a1e9807df5d64cea3b3e28bce36e1e95e4af438e4324208"
    "887ffabea2f8918f8be9db902e9a88a9123d5abbb570ead3a9d27a239499ee75b17691d02cc1698436b941b5b6979869"
    "eb78eb03eb12c02244d918df60169e8f08ff97f8b98f0d5de5a82f50a98dadaf1aa60bfd27e1a69ee5770d6dc34cdf8a"
    "1e74a3fad96d59cedc5088b7db82abcebb0870b7ef14dea438c73bbdcd1ade4be7346b44b02d83fc421c5dd816631684"
    "f16acb9798d49b59c56221581f629355b084ee712895ffb6d6d6c5bab7ac9cf9bde34059097c23b4ad24537203a7548e"
    "47e71fe590b59af8d928786dcff8af827a9c66a03f2caf5b31f3403bc37bc6be3cf6e42b0121573d8307cd212d583d2c"
    "ca9c843f57d7a1aa85ecc65ee4ce31b1674b8ec14d679f60c7d068e6d347aebbcf697ee5046ce1b9bd6b20ae1f8cbcd6"
    "bd997a108caff86e2e99ef1037f215c21a9458f79df936801faf255050caf715af72f9c73b95f1e301f37d4be73487fe"
    "1b2077dfbda5f0ec6085e738bbba06cf3eff6cf5bec58aec5988d9a67651f2bdc2c6e90a41a551a8ba40fec6e8a8dc7e"
    "c29a6dc8573b87ccfdf76a38f168b062854f524f5b6dff1a310e7702055bd84632e10f66f4ceffcdce05453d41826265"
    "258e63af1376e58bc472a1af574c00eccdf3754b4b3c5e8a1c2e610cac3ae04c1717d8874e8e6316fa18557007bdf469"
    "518fc7b6239421a7e2c965eda2513dc44b94b06f04e50eb41d4d2fe374a7c1338a94fe884ea59c2c784f1c399788e9a9"
    "177f40c949c59ec69d5faa419a930feb706ad113cd97357e5ccd20a7a4cf863148fdb2a62a5349a6534d03d4273c0224"
    "dc1aba6f242175aee12d9cd7e95ae000838df5f296633f7e48ff2eec3687292abaceef66a8fd50aba63c21cb71c4ba3b"
    "7979db1038cc61d08b3c4c740cb2bca7b72ebc24bc061908aec184a7e846a3cfc4e1dd6d464394eee95f36ce5234f1de"
    "042da700066978d8bb25bdae100364f122fa07e40da559bf650aaf6d779f7ed525d8f6a78dd14c50248081922b296e6f"
    "3b9170ee32099a931e2e06958fd319451bcbbe298e1f7637cf1c2092235f2941abef13e735c86c4e165cb0ed0bb9d23c"
    "048423de5601925d1f07f38879da706919e2d513e0c20c62cb359d33487ad2c4b50e44b003efa4b1981daba42cd61b5c"
    "9b18766462253e53c814cc8d7c9b6aa48417fd1fe4f5ad4b1c76f990af1161c92786bd5e7f4aa3db7ba686460fe7c9d1"
    "fd9df1392c492953a02627caa3a29ead42d763b89bbf63f7154b41e63579aa1db5150605cb4e66879f2b5489ab556fb3"
    "b7f3947eb0dcc314979dc9c9d9b3656322dcc3766b61b41ca44af84bc4b85529a8ffb2ea11101cf4266fa49068df9c8b"
    "389c17bcd044ac6c7a09c9d8139e297f57c9934d192f094ba4600fbb127c02c90d0ead45281143f2f5a5c3e5a99324bc"
    "107d1cea042e02ad8b3045fb7083db7773a495c54291e80e5b15d3f94c1221dd79185d1e78fb18df8ccfebf95cdc445b"
    "0da701d354a06c354ceea6d7da84779cf6350a1b8d424d059aa5a6732aa809a3126657d1aedd4467224b3ac77c11e3f8"
    "b7001d95a65f99adcd3fed4741f63398a9e9433b27fef9a40d38083f79b1e992674fbaa06b34efb0a4537c5e33fddd8b"
    "67736c1f1a0e8019a50470686097299aa9319f6cc41f4a551f19adacca4a82f9427871027eedf9c697ee0469fdd46653"
    "7bd69c232d3eb9a3932137c963142fff1289c5645f0469a12aa45edd4970788ee3b4bedf27130d21d5a6f2e30f050099"
    "7bb2b56af8081ec2648171419f73a81e6bd2669d303ac01bb10253a06d81b2edc77bde34d9dba83b1323a6e33c5a80bb"
    "dc39db52f6ba93937e46592ce525c710c3a09f8f004fc9691cefef0ec8a825fa6f7e88fdbdb41dd889e3726d00008178"
    "a558fd873bc0922393354cfb21083e39c5285de385aa47064995c0a053c43f538385ea41836d6b404d7d2f3ce75c0916"
    "1cbe4456a1dce3efee711061b9807dc14e8ce7ec70d3ec47c73c233f910d2d30e7c90f24233494654c8c8d3333e6d669"
    "bee96228593772fc7e444ea47b0d1026406b66d37adab284d3a1dfe987185e61878ecdc18c15a4d6616e31c7f6f76e90"
    "bb2fba42c925dd4639280318c610b8dd7e50ba7f559776e79f2d64dfe641a8741d88dfb7c89aac2fdc48c6ff56ba3d1a"
    "776a2d9d2a9b82106363e639aac3b0f49e88eb396a6799fd43a20cddda0e670f62260fbbb99d67a26716405348afc169"
    "333194f3047ece50a4db47a4576f420e856b9612d12d8ef017126c9927672f7072d1699422667f11fffa8e5f68f2f44c";

static const char EXPECTED_PRIV4896_HEX[] =
    "3de4c5f264b53f8936ccb279d03dbd050832c0a41a196069f54fc8824d1ef4cfc5b18e5ff541e55fb17d836bde067adb"
    "88ff2be90770dc4b4ac9782a20840d80d6596086c37ddf9c69ceb5e8bbed795c50aa6cc396471acff00ede382a31026b"
    "261e764aa77a5a90fccb31ce7e39945b8d178a43b0e0c6983529fbb12e6ab9cc9b0646c28451030960a21480e0447121"
    "890521178e123302e44200c0b401834264028389c298680b240d5122009148804a426c90488920138c138590a0823101"
    "495191124d2044248a340dc8c87142084824020201468a142404d1820992c28c04446221166523a66960b06461347110"
    "4551cb8871a146519b88242499494b00664290649196655c340612a6849928290422884136210992911939649404105b"
    "4661dac4505208059886019cb67103b0440987604992251c214009842920c92991b8244c82289080305996002225000b"
    "a9091146250ab14dd9163060b46001498a20231019437021c78d5930208a1421c8146d1b214a92082502078862340a22"
    "460ec108894c023003861108200a19309203136c8836618a92200296901845091848725980851a052c030584882064d1"
    "82909146859b4632a0c285d3486ca2080804c724a22606434272113141c3381004a72ce02449c03862144881dab644a1"
    "106e02867158b8219c888952b20c21c641941668a3b40c13092521c48059b4508c106dc828005c42105818081c4804c0"
    "327101258ac4000cd4848c0286202019495bb004193540e2265010c1212045099392001b148020a7219ab6911bb12c1c"
    "b52cdb9424a0444519c66824057061386988800c09b045cc464a2422640b22468328210c22318a028182306e52206519"
    "390922475104966c03324dd030201298309ba44dd4968598306a13458413833008066c0236068898412098919c444a18"
    "17280ca400988270d012021a371220a2508b4062d0960103b54904c9096146911bc0080032841cb66c51344514242c10"
    "a48c49464950b44900b15002926521454a0c1612d99421030122124662d822515c868011b54802290a43b82c8c386d08"
    "40209a000042862c013764032422048828d9489190b4810439449a18215a304508b67048063013880064484e02248641"
    "0452129631d388288a0061e32872008121042464993689c2b26912b470624249249260448828d0882484108404089163"
    "12721407028b86091ab589e31061c1904083966918280094b669c4168822c950a4444ae1c869e2064c44b020a3344a99"
    "c2095824699c14908a383019042013b40ddc02621b1189db086e2016324b362e4c8681c11029120946144065020912da"
    "a4100b053058446acc822ddc3401d9242a21360a22954c04a96c82c40512106989c271e0a224c0308dd2c40d8a160121"
    "a50d822846c39280802608c94465d84470091488241021d3320aa0c230e3c8680a2410d4124c20c28ccc20610116125c"
    "822112c88188a080d308310b21640a30428b120a0b168d44c211832028223426d3b09118a031948004da4251023025d9"
    "b20121c48d1c80815b0012240349d1464089826dccc488884260dc4868d0902999204112162d19b68064900d88980c58"
    "304ad1a82013478012150812b33192308da2c2052413284a027164088c08404a84b800a3220d00404e53384420108159"
    "880420c2091233701ab761622204c93409240749a142045b488553c06084a48598c4495ac6295b383103368c4c044853"
    "b689dc222854a20904252108250d1bb62903286a13978d001931c9424224c209d3a6681b108250b68110250d01b62122"
    "464020348d243569e4388adcb0708c9244d3168419446814084514254c81924d53903193982d19028dcc365008a3715a"
    "a08910362100092c19278a1ac545038505e1382400b40012910599a070802009cc408194280602831001964c01388289"
    "168acb082e02c18553a8241917504480648cb868e424004b104208b98103c5290c410592a62002820010b76424350c10"
    "3648112684d400518284884a1412028005a0320891a64c82022a22110c6436320bc75063868010036888162d8418019a"
    "147204276a4b86282422525b940c0844510b80015820094102698c0292c930252092054c984c12432198808448160a91"
    "088ac0462ad1b44c2329321ba01163240cd9464ce3c0609cc44de4b61123876c99533307fa3da862805bbeac71d5f319"
    "a558ba03683923cf66c5c9f6c751cff85d6f7a026c2fc8b7492e7133ebde8c815c0a7cd4466458ddacadef0f04e259a4"
    "da676f0a8a4e09e6fd19e074d7266306f4eabf0ec1f67e3b10aeb1577d313337eb2a7116687b6c7bc639fd6fc7ede5fb"
    "7022e97f01791c03a0228dc2cc90d6678176b37abdb01880fb3ec4b426fb009e2b5fd3938dfe36d93ab06897c49058cd"
    "a6a5df7e505718b2a2990d73b8729781e16a232b7aac32699167b4659db50de89701cb3524b69b668a538ffadc2ae05e"
    "2384a6888db65554aa8ddc39b97d53f403a16ac71f734b592460107c42f9fc34e0b3f64744150fe5123a7f3761453d21"
    "3d562413f2e297eb843f7cc00ff6425680f7c19cb56bd04b4b642b942a697dad7c2991b81886922efc70215d8debe63b"
    "17a2d556efe836f8ecea3ee2fcc290d8b4950958a733908c4a58d1ec29e928064d595c94e63bd90059bf20c2102b526e"
    "7c22755111b4c44936f965792cefbba4be77a4d2d946b040fe64b3d38e79590e37faae2434ef91860a910a605f6479be"
    "0063b945c8cf09596fd657120f8fa2cf21a770225cc2416fd6a476529143bca08d53b07e4f4adeaaaf9519a8b0679018"
    "e748344f6713bd749256fd37143c7db49dd3cd3016f176800030768d31342e3fddd4eec1f0990f2734ac4bb05017917b"
    "2f9a24b61a2a0638010708b2a21455ab42be3710c338557b3bd812316f9190fbe1601659a72a1ae888ab992e6002ad9d"
    "c4ee295dbc815ac28b4ab13c1285c43bfd02d1194380d8d65b6b7ccf56f7a1ce79946b8e59e37eb256babe53d399d7e3"
    "474cb33f5d093a871d19a7cf69e49d078f4072d2523078f2bc30450626eb7c6d255126893f17850028050975b1bc6bd9"
    "d3120e7a532b2d9fc7a76f92895d007038b948daf31ff17668a0099ea81ad9780a98450d1e61dd0687086ca13832db1a"
    "7c290cc7c8b3c5d09d09388e1ce67c666e22a026565ee00adae7d4128990015cf33189662895eabb356d99ad2602a6bf"
    "b832b11cd68d0ef2b267fe6cae041c8ad970b58de525a7a68719137bfbcc9bcb09f56c2ffaf82a98e2fe4f9691da5c80"
    "1391f278c9b449a8957880edebd2742bd074708fbf71ee5a3ab3b4e4028fbb2782ad4aa547c557702e3261799cac8f9c"
    "54d539bb85889775aaacb27dc6b6ac589a10f90a1ef204886c5b297648a1d4761f8ca9f8a02d9297958a69d8c5a67057"
    "7585078b8d92ff3c2119b7ea486aa3b6e0b8f9263197fe3f70a1cc8d5ca061615352570c92ef672bcd082f63458e0a0d"
    "9862feb5f57548830f5d98f1e94d0a447bb2513fa7f75585dceda68106ab5a000db1cc6f739f020592f499e1046b6aac"
    "6833d8c478a26601df13c8f3448c58a9c2d074c256261f0dd66818093f87d14e495320e41829590bfe3d2ccb9aa0afd4"
    "8730bc37f7a9d41b544abf8bfd1f789ccd04ffa9bc101d99d39f7ec0230075ae848f0614a1951c3e97dfa1df4fd9b040"
    "0b0a09598f3d3fc3d903bcbe041cd0e91bce44c87852903437feb5e7fdfa9c696c9ee08c5786c5f57f2cc647fc01a90d"
    "fb113e3cef54471be3739becb954b0264104833ee0dcbefe36762e1df189d50fa9251a0bdcea7f80b6117eb25621006b"
    "a930086b8787bacd4260708660b0ec413bab820e844c0266df23094d1d0b4d1ef2be74a867dd1e789eb65d158c6dd62f"
    "9e93eddc81614c22ccb3bdb9444ecf645c91bf1277c0c57f75e58c4995d2a491405c35bdac46c1cf1da0341cc50de454"
    "4e101bbd74ef9fd3567019c407c10ccefa079178b00c92f4eec22a911e1606c348d6088f1cf8af561fc346e378247341"
    "d156cef59157327e1d8eca2c8fdb69b48d9f233fd386ac9ddbb4b2a80012e1aa7de9c7616ec4922d068164d7e0d8013a"
    "91385e1ab13b853121a588331974c33ef8dac8af3c71c1190bb29257e8f377046aa9a013d56b868db5b003a4b354b4c7"
    "a44ef275775a8402171274e767125c9d7a6815bf803a00c22c6265c5a8fde576b84803c6a37310f0942845ef3e58a60a"
    "736afefe7ad62a7277880b6b96250f86ea855e233f136b9dbaf2591ee34f98b3dcd768de2b278388772fa6d9d352e8a0"
    "9f18dae28274e5af4a019661c62e058e0867f697a0d37b2201623655f71678ee05445acc52ba2e5ea0025a49b6a3fbf6"
    "c470bf040599bdd10d36a3de17bda8f2b7af5af35d0baacc8bb90d8094013ce83cd1908b665fc213db46b28a988eae9b"
    "984361ad10959e2d8bde93e18809888a60ccda59322cd8b75a6ac16cd950b2990e971cc05bf8f537965043873d6510e2"
    "958cfdf4aa75da69e8e4fc6b2ac072e5b8709a2ed405d0424e0e530a22b6e113b1b3e8dff7a8bc5b0c58b86ecc028f55"
    "d0a7cdb97709bf6a3985f4b25cd767eb993efc5b360aeb720b31281e9f0ddd366c9ddc31d004a718a25b9528e80706be"
    "757da7ab16c1a39104d0ebbe9a26e11257edd9f1d5d4cfaaa92bfed00c24d04efedce1cd43c4d1e75e56cfa2f9654f90"
    "8a52ae4ab400c084508c57db97609b0f7fa0248f60e1b2e01c3fa798192cbeedb08e201f7c87ad0b4500d7a636c63f1c"
    "ceed6abc3d7e3272534a49d88263804c0108712eac72fc1fce4968c625224081a54cf956c4f2a29181aac544fb410d09"
    "57f1910921abb25f9e1701278d4b2ef8722f67c001d2f278ea545286f9c0f1347b1ea9c1015c82716467b98e21243129"
    "af7a8c956117dcac2a5dfeae4a90a855cc1721ccc83cefe0d682a3af4db7ad2d73b11aa51da89aefed7593372427eb6b"
    "3502f78d2a2f7eb57edacae9ab810a518eae7d5c3ccdc3704b6d62cf9e939c95a853316a9260b28add713689c65efcc6"
    "3f9700cf1989b4bcf08c2004d863ba6d3a06c98435ec4ab0baab5b12f90b4dbb39ff2cdc036d79b2d4347e361997d7e5"
    "598bb4e22499352f5bbae929340b2ffd28da1bae54dbce9674373d37a1a969479f19fc8a287ce1e63c91d63f6b346526"
    "f42ba644345b73be3aacca903589d9debd5a40a441e73bbcbfc78f3169f5cfc4e8b17ab1f71ad0b43a656d3468c7d6ad"
    "8320aaa4da130c9000409d26e41a2199076a845bf344f3a8f85318627fa124e83d38f27c49340f80cf89aab22e73df8a"
    "9b977812ae7e4430cdfa8bbb23008f702e35177d10e790693fa14b6b4f417ca842c804f39449186cb28d9ebc08d3e72e"
    "000c41ce1935ebc3a9047b66215c86e663d7795de0309953f6b0f7ba9e8f7426855d2b8e6aefc1f82e5d7ce969a4ac1b"
    "86dcb6df3378b4d39955c4798aef817a90c47cc3f5d391906c6c14d0c935cb7b4b5da9e07e3a4abea4b1f6190a999998"
    "2696ac174dee36434b6a41a0293fe6874ecc7fca2188c057ce69c063f502a074c70bea0ed3b40b6270bd876bbfa0c078"
    "d8ef894da38d666359964f90dcb63f2698f58dcb41d4f1df8109699ed5f5c590db904bf9574d164037e17c7f59e99ffd"
    "e4f11371e674b9d2539301b02cab94bb50c7a9e90d5999c972f6b1a6c6b1b5012c8b724de035eb2bb935e18102258b55"
    "ac6d3854953c0d5e6d72bb08121febe586d87cdd9797490bffefad9ed5c2fa06b29275176d815affaea7d1cb1a75be21"
    "7649a3e312579eed263f35a5476211f19865feebbd7d62605ee08aab3952de202631ea0bf14e5ba222a3eb6f71827447"
    "e10a4d40d103632850bd07229c8011b6a2322429c5120b99956751b9ffa6c63fdca44174417f4041aa15990ba3616275"
    "1172723125b1e9a2354b6876d56fd008f3dc2194b66d06abb22319f6d09e6a0cbacb0d4354c368a45201edeeb085beb9"
    "5173112faacc17960d1c26ba3cee9bf9fa198a77377a9caf44fdf7a9c6c548a5da65009a5807be71d36406a94b85c0f4"
    "1930532a9b647b5196d9812978b0bab4d0d80f1816b38e607fcde0df447c0c08b09e072cfefb315b791e733c1d8890d6"
    "ec301803265da1d04fabc4dbb034dd82bb4a01058be324e7239b1c92d653826aba1991ba9a1ea73ee71d895ff76cb129"
    "45c253c4fc95f43eafa2dcb6575b6cb7bd40e6f60e52eedeb924f8b40685b36ca96cb44884c3df47fe1bba7b804dd744"
    "73f3dd070b9ddef4b234c82f732c31c9779ada29ec4a7f94b83185fa61c7bef6c43830c9abf4c2efbafbd80a186387ee"
    "8c644e6ec5b95e731e18d464d6a2b12a24da0808dc5ff683fee7419d0e1f11ace24d40809359d5ac1ffcb9b27043627a"
    "e16da266efb55306aedb87976ff6c9bffa07b0c808ffe7a9ba613f25b308793702d9d3b86344f5e410028de94a8a8851"
    "6a081b9a216d9cda8365269fd4bd0904fae91c87e15e65d747174e22682c3c59bf6effb4d0bb0d07aa798397be7e4e0b"
    "6898a53a45c621e5028a3509fa8e15d716c1a5b88c6bbb41b520136853cf97dd504c977cec83b0f5890ef0149d6cac8d"
    "4c17bb4cd50bfea58ea6f23959ca601aba90dce17e39ef7349271cd55eb82af689ce38f4e9a6ee3a66eeadf425289b16"
    "3cf1f7fed645d7d764afcbb473a55344981439a0ba091aa2bb1ff82780d2dc03ca92b7897033410bb0c144ff7703c5db"
    "92aa3c11cd62f9dc52f7b8647688e3c8e4f09a8797fb8123df654af6e062c0accb340286496a08f135af87f7cbe5c992"
    "654608b8776f1c1c7f914f0f1be6045d26fe802972ba66e5a6ddecb12a2ec77948b2834e1d199f562a999f50c8b9f2da";

static void test_pq01_keygen_byte_identity_vs_spec_vector(void) {
  TEST_START("PQ-01 KeyGen byte-identity vs MXD-PQ-01 spec vector");

  uint8_t leaf_xi[32];
  TEST_ASSERT(hex_to_bytes(LEAF_XI32_HEX, leaf_xi, 32) == 0,
              "leaf_xi32 hex decode succeeds");

  uint8_t pub_out[2592], priv_out[4896];
  TEST_ASSERT(mxd_pq01_keygen_at_leaf(leaf_xi, pub_out, priv_out) == 0,
              "mxd_pq01_keygen_at_leaf returned 0");

  uint8_t expected_pub[2592], expected_priv[4896];
  TEST_ASSERT(hex_to_bytes(EXPECTED_PUB2592_HEX, expected_pub, 2592) == 0,
              "expected pub2592 hex decode succeeds");
  TEST_ASSERT(hex_to_bytes(EXPECTED_PRIV4896_HEX, expected_priv, 4896) == 0,
              "expected priv4896 hex decode succeeds");

  TEST_ASSERT(memcmp(pub_out, expected_pub, 2592) == 0,
              "pub2592 byte-identical to spec vector");
  TEST_ASSERT(memcmp(priv_out, expected_priv, 4896) == 0,
              "priv4896 byte-identical to spec vector");

  TEST_END("PQ-01 KeyGen byte-identity vs MXD-PQ-01 spec vector");
}

int main(void) {
  printf("Starting PQ-01 tests...\n");

  test_pq01_master_independent_from_slip10();
  test_pq01_master_reproducible();
  test_pq01_path_account_separation();
  test_pq01_keygen_deterministic_round_trip();
  test_pq01_keygen_byte_identity_vs_spec_vector();

  printf("All PQ-01 tests passed\n");
  return 0;
}
