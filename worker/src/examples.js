// Real outputs captured 2026-10-02 from live read-only runs (tools/capture-examples.mjs).
// The /verify-signature example is the EIP-712 spec's "Ether Mail" test vector.
export default {
 "tx": {
  "input": {
   "chain": "base",
   "hash": "0xcdfb89a7bc6b072c43e53cb2c1294f4889e40957196123cf9a34cce7d346c0a9"
  },
  "output": {
   "kind": "tx",
   "chain_id": 8453,
   "status": "success",
   "risk": "LOW",
   "findings": [],
   "summary": [
    "0x1d7f…7E95 sent 0.180935 USDC to 0x26fa…d476."
   ],
   "tx": {
    "hash": "0xcdfb89a7bc6b072c43e53cb2c1294f4889e40957196123cf9a34cce7d346c0a9",
    "from": "0x1d7f97D26ae2C01F9b01Fc252B73Cf0Db3397E95",
    "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "value_wei": "0",
    "value_eth": "0",
    "nonce": "1567875",
    "block": "52074990",
    "gas_used": "45059",
    "fee_wei": "271317298455",
    "fee_eth": "0.000000271317298455",
    "contract_created": null,
    "timestamp": "2026-10-02T11:08:47.000Z"
   },
   "call": {
    "selector": "0xa9059cbb",
    "function": "transfer(address,uint256)",
    "args": [
     "0x26fa1279D034BACb3BACd98119e767f9D884d476",
     "180935"
    ],
    "guessed": false
   },
   "events": [
    {
     "type": "erc20_transfer",
     "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
     "from": "0x1d7f97D26ae2C01F9b01Fc252B73Cf0Db3397E95",
     "to": "0x26fa1279D034BACb3BACd98119e767f9D884d476",
     "amount": "180935",
     "symbol": "USDC",
     "decimals": 6,
     "text": "0x1d7f…7E95 sent 0.180935 USDC to 0x26fa…d476"
    }
   ],
   "unknown_events": []
  }
 },
 "verify": {
  "input": {
   "chain": "ethereum",
   "address": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
   "typedData": {
    "types": {
     "EIP712Domain": [
      {
       "name": "name",
       "type": "string"
      },
      {
       "name": "version",
       "type": "string"
      },
      {
       "name": "chainId",
       "type": "uint256"
      },
      {
       "name": "verifyingContract",
       "type": "address"
      }
     ],
     "Person": [
      {
       "name": "name",
       "type": "string"
      },
      {
       "name": "wallet",
       "type": "address"
      }
     ],
     "Mail": [
      {
       "name": "from",
       "type": "Person"
      },
      {
       "name": "to",
       "type": "Person"
      },
      {
       "name": "contents",
       "type": "string"
      }
     ]
    },
    "primaryType": "Mail",
    "domain": {
     "name": "Ether Mail",
     "version": "1",
     "chainId": 1,
     "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
     "from": {
      "name": "Cow",
      "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
     },
     "to": {
      "name": "Bob",
      "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
     },
     "contents": "Hello, Bob!"
    }
   },
   "signature": "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c"
  },
  "output": {
   "kind": "signature",
   "chain_id": 1,
   "address": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
   "valid": true,
   "method": "ecrecover",
   "recovered": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
   "account_kind": null,
   "digest": "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
   "digest_type": "eip712",
   "notes": []
  }
 },
 "token": {
  "input": {
   "chain": "base",
   "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  },
  "output": {
   "kind": "token",
   "chain_id": 8453,
   "risk": "MEDIUM",
   "findings": [
    {
     "code": "SOURCE_VERIFIED",
     "severity": "INFO",
     "message": "Source verified on Sourcify as FiatTokenProxy."
    },
    {
     "code": "UPGRADEABLE_PROXY",
     "severity": "MEDIUM",
     "message": "Upgradeable proxy (ZeppelinOS-style): whoever controls the upgrade can replace this contract's code at any time, including with code that takes funds approved to it."
    },
    {
     "code": "ADMIN_IS_EOA",
     "severity": "MEDIUM",
     "message": "The proxy admin 0x4fc7850364958d97B4d3f5A08f79db2493f8cA44 is a single wallet (EOA): one private key can upgrade this contract."
    },
    {
     "code": "IMPLEMENTATION_VERIFIED",
     "severity": "INFO",
     "message": "Implementation 0x2Ce6311ddAE708829bc0784C967b7d77D19FD779 is verified on Sourcify as FiatTokenV2_2."
    },
    {
     "code": "OWNER_IS_EOA",
     "severity": "MEDIUM",
     "message": "owner() is 0x3ABd6f64A422225E61E435baE41db12096106df7, a single wallet (EOA): one private key controls the owner-only functions."
    },
    {
     "code": "MINT_FUNCTION",
     "severity": "MEDIUM",
     "message": "Someone (usually the owner or an admin role) can create new tokens (a mint function), which dilutes holders: mint. The owner, 0x3ABd6f64A422225E61E435baE41db12096106df7, is a single wallet."
    },
    {
     "code": "PAUSE_FUNCTION",
     "severity": "MEDIUM",
     "message": "Someone (usually the owner or an admin role) can pause transfers, freezing everyone's tokens: pause, unpause. The owner, 0x3ABd6f64A422225E61E435baE41db12096106df7, is a single wallet."
    },
    {
     "code": "BLOCKLIST_FUNCTION",
     "severity": "MEDIUM",
     "message": "Someone (usually the owner or an admin role) can block specific addresses from moving their tokens (a blocklist): blacklist, unBlacklist, updateBlacklister. The owner, 0x3ABd6f64A422225E61E435baE41db12096106df7, is a single wallet."
    },
    {
     "code": "SCOPE",
     "severity": "INFO",
     "message": "This profile doesn't detect honeypots or simulate transfers: a token can still block selling or take hidden fees in ways a read-only check can't see."
    }
   ],
   "token": {
    "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "name": "USD Coin",
    "symbol": "USDC",
    "decimals": 6,
    "total_supply": "4354369109704165",
    "total_supply_formatted": "4354369109.704165"
   },
   "owner_powers": [
    {
     "code": "MINT_FUNCTION",
     "text": "can create new tokens (a mint function), which dilutes holders",
     "functions": [
      "mint"
     ]
    },
    {
     "code": "PAUSE_FUNCTION",
     "text": "can pause transfers, freezing everyone's tokens",
     "functions": [
      "pause",
      "unpause"
     ]
    },
    {
     "code": "BLOCKLIST_FUNCTION",
     "text": "can block specific addresses from moving their tokens (a blocklist)",
     "functions": [
      "blacklist",
      "unBlacklist",
      "updateBlacklister"
     ]
    }
   ],
   "profile": {
    "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "chain": "base",
    "code_size": 1852,
    "verified": true,
    "name": "FiatTokenProxy",
    "proxy": {
     "type": "zeppelinos",
     "implementation": "0x2Ce6311ddAE708829bc0784C967b7d77D19FD779",
     "admin": "0x4fc7850364958d97B4d3f5A08f79db2493f8cA44",
     "admin_kind": "eoa",
     "implementation_has_code": true,
     "implementation_verified": true,
     "implementation_name": "FiatTokenV2_2"
    },
    "owner": {
     "function": "owner()",
     "address": "0x3ABd6f64A422225E61E435baE41db12096106df7",
     "kind": "eoa"
    }
   }
  }
 }
};
