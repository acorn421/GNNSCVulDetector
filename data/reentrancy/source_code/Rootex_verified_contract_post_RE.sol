/*
 * ===== SmartInject Injection Details =====
 * Function      : post
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moved Market Creation Before Token Transfer**: The market entry is now stored in the markets mapping before the actual token transfer occurs, creating a vulnerable window.
 * 
 * 2. **Added External Token Validation Call**: Introduced an external call to a token contract for "validation" that can trigger reentrancy. This call happens after the market is created but before tokens are actually transferred.
 * 
 * 3. **Created Vulnerable State Window**: Between market creation and token transfer, a reentrant call can:
 *    - Create additional market entries with the same tokens
 *    - Increment offerRef multiple times
 *    - Allow the same tokens to back multiple market orders
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls post() with malicious token contract address
 * - Market entry is created with offerRef=N
 * - External validation call triggers reentrancy
 * - Reentrant call creates another market entry with offerRef=N+1
 * - Both markets reference the same tokens but only one actual transfer occurs
 * - Attacker now has two market entries backed by tokens for only one
 * 
 * **Transaction 2 (Exploitation)**:
 * - Other users call acquire() on both market entries
 * - First acquire() succeeds and transfers tokens
 * - Second acquire() fails or transfers from attacker's other holdings
 * - Attacker has effectively "duplicated" their token backing
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial post() call to set up the duplicated market entries
 * - Exploitation requires separate acquire() calls from other users or the attacker
 * - The state corruption (multiple markets for same tokens) persists between transactions
 * - Single-transaction exploitation is prevented by the move() function's balance checks
 * 
 * **Realistic Nature:**
 * - Token validation calls are common in DeFi protocols
 * - External calls for compliance or oracle checks are realistic
 * - The vulnerability is subtle and maintains original functionality
 * - The CEI (Checks-Effects-Interactions) pattern violation is realistic
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Create market entry with temporary offerRef
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    Market memory mi;
    mi.askCoin = askCoin;
    mi.ownCoin = ownCoin;
    mi.ask2own = ask2own;
    mi.maker = msg.sender;
    mi.value = value;
    mi.time = time;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store market before token transfer (vulnerable state)
    uint256 currentRef = ++offerRef;
    markets[currentRef] = mi;
    
    // External call to token contract for validation/transfer - VULNERABLE POINT
    // This allows reentrancy before final state updates
    if (ownCoin != bytes32(0)) {
        // Simulate external token contract call that could trigger reentrancy
        address tokenContract = address(uint160(uint256(ownCoin)));
        // Solidity 0.4.24 does not support address.code.length, so we use extcodesize
        uint256 size;
        assembly { size := extcodesize(tokenContract) }
        if (size > 0) {
            // This call can trigger reentrancy, allowing multiple market entries
            // to be created with the same tokens before actual transfer
            // Note: Solidity 0.4.24 does not support abi.encodeWithSignature, using bytes4 signature
            bytes4 sig = bytes4(keccak256("validateTransfer(address,address,uint256)"));
            // For compatibility, pad arguments manually
            bytes memory data = new bytes(4 + 32*3);
            assembly {
                mstore(add(data, 32), sig)
                mstore(add(data, 36), caller)
                mstore(add(data, 68), address())
                mstore(add(data, 100), value)
            }
            // Call the external contract
            tokenContract.call(data);
            // Ignore the result for backward compatibility
        }
    }
    
    // Perform actual token transfer after external call
    move (ownCoin, msg.sender, address(this), value);
    
    // Update market state after transfer (too late to prevent reentrancy)
    markets[currentRef].value = value; // Redundant but maintains state consistency
    
    emit Sell (currentRef, mi.askCoin, mi.ownCoin, mi.ask2own, mi.maker);
    return true;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
