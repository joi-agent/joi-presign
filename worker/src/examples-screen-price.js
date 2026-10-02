// Real outputs captured 2026-10-02 from live read-only runs (tools/capture-examples-screen-price.mjs).
export default {
 "screen": {
  "input": {
   "chain": "ethereum",
   "address": "0x08723392Ed15743cc38513C4925f5e6be5c17243"
  },
  "output": {
   "address": "0x08723392Ed15743cc38513C4925f5e6be5c17243",
   "sanctioned": true,
   "matches": [
    {
     "entity": "LAZARUS GROUP",
     "currency_label": "ETH",
     "sdn_uid": 27307,
     "programs": [
      "DPRK3"
     ]
    }
   ],
   "list_published": "2026-10-01",
   "list": {
    "name": "OFAC SDN (digital currency addresses)",
    "source": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML",
    "published": "2026-10-01",
    "evm_address_count": 124,
    "generated_at": "2026-10-02T13:05:16Z"
   },
   "checked_at": "2026-10-02T13:06:44.000Z",
   "chain_id": 1,
   "kind": "eoa",
   "warnings": [],
   "notice": "Screening against the OFAC SDN list only; not legal advice; absence from the list is not a clearance."
  }
 },
 "price": {
  "input": {
   "chain": "base",
   "asset": "ETH"
  },
  "output": {
   "asset": "ETH",
   "chain": "base",
   "chain_id": 8453,
   "price": "2758.51213113",
   "currency": "USD",
   "decimals": 8,
   "updated_at": "2026-10-02T13:04:17.000Z",
   "age_seconds": 147,
   "stale": false,
   "heartbeat_seconds": 1200,
   "feed": "0xa4250cE1aA15Ff4cb5E5a8655293b65694e436Ed",
   "description": "ETH / USD",
   "round_id": "18446744073709634469",
   "source": "Chainlink data feed (latestRoundData)"
  }
 }
};
