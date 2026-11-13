'use strict';
// Entity catalogue. Higher priority wins when spans overlap.
const TYPES = {
  SSN:     { prefix: 'SSN',     priority: 100 },
  CARD:    { prefix: 'CARD',    priority: 95 },
  EMAIL:   { prefix: 'EMAIL',   priority: 90 },
  ACCOUNT: { prefix: 'ACCOUNT', priority: 85 },
  PHONE:   { prefix: 'PHONE',   priority: 80 },
  ADDRESS: { prefix: 'ADDRESS', priority: 70 },
  PERSON:  { prefix: 'CLIENT',  priority: 60 },
  MONEY:   { prefix: 'AMOUNT',  priority: 50 },
};
const PREFIX_TO_TYPE = Object.fromEntries(Object.entries(TYPES).map(([t, v]) => [v.prefix, t]));
const TOKEN_SOURCE = '\\[(?:CLIENT|SSN|CARD|EMAIL|ACCOUNT|PHONE|ADDRESS|AMOUNT)_\\d+\\]';
const tokenRegex = () => new RegExp(TOKEN_SOURCE, 'g');
const typeOfToken = (t) => { const m = /^\[([A-Z]+)_\d+\]$/.exec(t); return m ? PREFIX_TO_TYPE[m[1]] : null; };
module.exports = { TYPES, tokenRegex, typeOfToken };
