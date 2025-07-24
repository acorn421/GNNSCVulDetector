/*
 * ===== SmartInject Injection Details =====
 * Function      : post
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that creates predictable market manipulation opportunities. The vulnerability works by:
 * 
 * 1. **Timestamp-Dependent Market Advantages**: Early market makers (first 10 offers) receive bonuses based on block.timestamp and block.number, creating up to 150% better exchange rates
 * 2. **Predictable Block Properties**: Uses simple modulo operations on block.timestamp and block.number that miners can manipulate
 * 3. **Stateful Accumulation**: The vulnerability requires multiple transactions because attackers must first create multiple market offers to accumulate better rates, then exploit them through subsequent take/acquire operations
 * 4. **Multi-Transaction Exploitation**: 
 *    - Transaction 1-10: Attacker posts offers during favorable timestamp/block conditions to get enhanced rates
 *    - Transaction 11+: Attacker or accomplices take advantage of the stored enhanced rates in the markets mapping
 * 5. **State Persistence**: The enhanced ask2own ratios are permanently stored in the markets mapping, creating lasting advantage
 * 
 * The exploit requires timing multiple transactions across different blocks with specific timestamp characteristics, making it impossible to execute in a single transaction while creating genuine economic advantage for attackers who can predict or influence block properties.
 */
pragma solidity ^0.4.24;

contract Rootex {
  string public name;
  string public symbol;
  uint8 public decimals;

  string public author;
  uint public offerRef;
  uint256 internal PPT;

  bytes32 internal SYMBOL;
  mapping (bytes32 => uint256) public limits;
  mapping (bytes32 => uint256) public supplies;
  mapping (bytes32 => mapping (address => uint256)) public balances;

  mapping (uint => Market) public markets;
  struct Market {
    bytes32 askCoin;
    bytes32 ownCoin;
    uint256 ask2own;
    uint256 value;
    uint256 taken;
    address maker;
    uint time; }

  event Transfer (address indexed from, address indexed to, uint256 value);
  event Move (bytes32 indexed coin, address indexed from, address indexed to, uint256 value);
  event Sell (uint refno, bytes32 indexed askCoin, bytes32 indexed ownCoin, uint256 ask2own, address indexed maker);
  event Buy (uint indexed refno, address indexed taker, uint256 paidValue);

  constructor () public {
    PPT = 10**18;
    decimals = 18;
  }

  function tocoin (string memory coinSymbol)
  internal pure returns (bytes32) {
    return (keccak256(abi.encodePacked(coinSymbol)));
  }

  function move (bytes32 coin, address from, address to, uint256 value)
  internal {
    require (value<=balances[coin][from]);
    require (balances[coin][to]+value>balances[coin][to]);
    uint256 sum = balances[coin][from]+balances[coin][to];
    balances[coin][from] -= value;
    balances[coin][to] += value;
    assert (balances[coin][from]+balances[coin][to]==sum);
  }

  function mint (bytes32 coin, address to, uint256 value)
  internal {
    require (limits[coin]==0||limits[coin]>=supplies[coin]+value);
    require (balances[coin][to]+value>balances[coin][to]);
    uint256 dif = supplies[coin]-balances[coin][to];
    supplies[coin] += value;
    balances[coin][to] += value;
    assert (supplies[coin]-balances[coin][to]==dif);
  }

  function burn (bytes32 coin, address from, uint256 value)
  internal {
    require (value<=balances[coin][from]);
    uint256 dif = supplies[coin]-balances[coin][from];
    supplies[coin] -= value;
    balances[coin][from] -= value;
    assert (supplies[coin]-balances[coin][from]==dif);
  }

  function swap (bytes32 coin1, uint256 value1, bytes32 coin2, uint256 value2)
  internal {
    burn (coin1, msg.sender, value1);
    mint (coin2, msg.sender, value2);
  }

  function deduct (Market storage mi, uint256 value)
  internal {
    uint256 sum = mi.value+mi.taken;
    mi.value -= value;
    mi.taken += value;
    assert (mi.value+mi.taken==sum);
  }

  function take (uint refno, address taker, uint256 fitValue)
  internal returns (uint256) {
    Market storage mi = markets[refno];
    require (mi.value>0&&mi.ask2own>0, "#data");
    require (mi.time==0||mi.time>=now, "#time");
    uint256 askValue = PPT*mi.value/mi.ask2own;
    uint256 ownValue = fitValue*mi.ask2own/PPT;
    if (askValue>fitValue) askValue = fitValue;
    if (ownValue>mi.value) ownValue = mi.value;
    move (mi.askCoin, taker, mi.maker, askValue);
    move (mi.ownCoin, address(this), taker, ownValue);
    deduct (mi, ownValue);
    return askValue;
  }

  // PUBLIC METHODS

  function post (bytes32 askCoin, bytes32 ownCoin, uint256 ask2own, uint256 value, uint time) public returns (bool success) {
    require (time==0||time>now, "#time");
    require (value>0&&ask2own>0, "#values");
    move (ownCoin, msg.sender, address(this), value);
    Market memory mi;
    mi.askCoin = askCoin;
    mi.ownCoin = ownCoin;
    mi.ask2own = ask2own;
    mi.maker = msg.sender;
    mi.value = value;
    mi.time = time;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Timestamp-dependent market advantage: create better exchange rates for early market makers
    // Uses block.timestamp and block.number to create predictable market manipulation opportunities
    if (offerRef < 10) {
        // Early market makers get timestamp-based bonus - exploitable by mining/timestamp manipulation
        uint256 timestampBonus = (block.timestamp % 100) + 1; // 1-100 bonus based on timestamp
        uint256 blockBonus = (block.number % 50) + 1; // 1-50 bonus based on block number
        
        // Apply cumulative bonus to exchange rate (this creates stateful advantage)
        mi.ask2own = mi.ask2own * (100 + timestampBonus + blockBonus) / 100;
        
        // Store the block context for potential future reference
        mi.time = mi.time > 0 ? mi.time : block.timestamp + (block.number % 3600); // Use block properties as fallback
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    markets[++offerRef] = mi;
    emit Sell (offerRef, mi.askCoin, mi.ownCoin, mi.ask2own, mi.maker);
    return true;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function unpost (uint refno) public returns (bool success) {
    Market storage mi = markets[refno];
    require (mi.value>0, "#data");
    require (mi.maker==msg.sender, "#user");
    require (mi.time==0||mi.time<now, "#time");
    move (mi.ownCoin, address(this), mi.maker, mi.value);
    mi.value = 0;
    return true;
  }

  function acquire (uint refno, uint256 fitValue) public returns (bool success) {
    fitValue = take (refno, msg.sender, fitValue);
    emit Buy (refno, msg.sender, fitValue);
    return true;
  }

  function who (uint surf, bytes32 askCoin, bytes32 ownCoin, uint256 ask2own, uint256 value) public view returns (uint found) {
    uint pos = offerRef<surf?1:offerRef-surf+1;
    for (uint i=pos; i<=offerRef; i++) {
      Market memory mi = markets[i];
      if (mi.askCoin==askCoin&&mi.ownCoin==ownCoin&&mi.value>value&&mi.ask2own>=ask2own&&(mi.time==0||mi.time>=now)) return(i);
    }
  }

  // ERC20 METHODS

  function balanceOf (address wallet) public view returns (uint256) {
    return balances[SYMBOL][wallet];
  }

  function totalSupply () public view returns (uint256) {
    return supplies[SYMBOL];
  }

  function transfer (address to, uint256 value) public returns (bool success) {
    move (SYMBOL, msg.sender, to, value);
    emit Transfer (msg.sender, to, value);
    return true;
  }

  function transfer (bytes32 coin, address to, uint256 value) public returns (bool success) {
    move (coin, msg.sender, to, value);
    emit Move (coin, msg.sender, to, value);
    return true;
  }
}