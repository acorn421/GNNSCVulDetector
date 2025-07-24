/*
 * ===== SmartInject Injection Details =====
 * Function      : unpost
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Vulnerability Changes Made:**
 * 
 * 1. **Added External Callback**: Introduced an external call `mi.maker.call()` that attempts to notify the maker about the unpost operation. This callback happens AFTER the funds transfer but BEFORE the state update (`mi.value = 0`).
 * 
 * 2. **Preserved Value in Local Variable**: Added `uint256 pendingAmount = mi.value` to track the amount being withdrawn, which is passed to the callback.
 * 
 * 3. **Maintained Checks-Effects-Interactions Violation**: The function still violates the CEI pattern by performing external calls (`move` and callback) before updating the critical state (`mi.value = 0`).
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a market post with a malicious contract as the maker
 * - The malicious contract implements the `onUnpost` callback function
 * - Market state is established with `mi.value > 0`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `unpost()` from their malicious contract
 * - Function passes all checks since `mi.value > 0`
 * - `move()` transfers funds to the attacker
 * - `onUnpost` callback is triggered on the malicious contract
 * - **Reentrancy occurs**: The callback calls `unpost()` again
 * - Since `mi.value` is still > 0 (not updated yet), the second call passes all checks
 * - This creates a loop where funds can be drained multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The market must be created in a prior transaction for the vulnerability to exist
 * 2. **Callback Setup**: The attacker needs to deploy a malicious contract that implements the callback logic
 * 3. **Accumulated State**: The vulnerability depends on the market state (`mi.value > 0`) persisting between the external call and state update
 * 4. **Sequential Dependency**: The exploit requires the specific sequence: market creation → unpost call → reentrancy → state manipulation
 * 
 * **Realistic Exploitation:**
 * The malicious contract's `onUnpost` callback can:
 * - Call `unpost()` recursively until gas limits are reached
 * - Drain multiple markets if the attacker controls multiple market posts
 * - Manipulate market state while the contract is in an inconsistent state
 * - The vulnerability is subtle because the callback appears to be a legitimate notification mechanism
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
    markets[++offerRef] = mi;
    emit Sell (offerRef, mi.askCoin, mi.ownCoin, mi.ask2own, mi.maker);
    return true;
  }

  function unpost (uint refno) public returns (bool success) {
    Market storage mi = markets[refno];
    require (mi.value>0, "#data");
    require (mi.maker==msg.sender, "#user");
    require (mi.time==0||mi.time<now, "#time");
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Track pending withdrawals to prevent immediate double-spending
    uint256 pendingAmount = mi.value;
    
    // External call before state update - creates reentrancy window
    move (mi.ownCoin, address(this), mi.maker, mi.value);
    
    // Add external callback to maker (common pattern for notifications)
    // This creates the reentrancy opportunity
    if (isContract(mi.maker)) {
        // .call is used to allow fallback
        (bool callSuccess,) = mi.maker.call(
            abi.encodeWithSignature("onUnpost(uint256,bytes32,uint256)", refno, mi.ownCoin, pendingAmount)
        );
        // Don't revert on callback failure to maintain usability
    }
    
    // State update happens after external calls - vulnerability window
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    mi.value = 0;
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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

  // Helper function to detect contracts (for pre-0.8.0 solidity)
  function isContract(address addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(addr) }
    return size > 0;
  }
}
