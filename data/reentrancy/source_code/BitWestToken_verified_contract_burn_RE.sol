/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external callback after state updates but before event emission. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `msg.sender.call()` after state modifications (balanceOf and totalSupply updates)
 * 2. The callback invokes `onTokenBurn(uint256)` on the caller if it's a contract
 * 3. State changes occur before the external call, violating the Checks-Effects-Interactions pattern
 * 4. The callback continues execution regardless of success, maintaining function behavior
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker contract calls `burn()` with legitimate value
 *    - State is updated (balance reduced, totalSupply decreased)
 *    - Callback triggers `onTokenBurn()` in attacker contract
 *    - Attacker contract records the burn but doesn't exploit yet
 * 
 * 2. **Transaction 2**: Attacker contract calls `burn()` again with same or different value
 *    - During callback, attacker can now call other contract functions (like `transfer()`)
 *    - The attacker can exploit the fact that their balance was already reduced in previous burns
 *    - Can potentially transfer tokens they technically shouldn't have based on accumulated state
 * 
 * 3. **Transaction 3+**: Continued exploitation through accumulated state inconsistencies
 *    - Each burn creates a window where external calls can manipulate state
 *    - Multiple burns can create compounding inconsistencies
 *    - Attacker can exploit the accumulated state changes across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction exploitation is limited by gas and call stack depth
 * - The vulnerability leverages state persistence between transactions
 * - Each burn call creates incremental state changes that accumulate
 * - The attacker needs multiple calls to build up exploitable state inconsistencies
 * - The callback mechanism allows for complex multi-step exploitation patterns
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world patterns where token contracts notify external systems about burns, which is common in DeFi protocols for reward distribution or cross-chain operations.
 */
pragma solidity ^0.4.13;

contract BitWestToken {
    address public owner;
    string  public name;
    string  public symbol;
    uint8   public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
      owner = 0xe6C37d321aB3E3669C67347F9cd525b769459FcA;
      name = 'BitWest Token';
      symbol = 'BWT';
      decimals = 18;
      totalSupply = 2000000000000000000000000000;  // 2 billion
      balanceOf[owner] = 2000000000000000000000000000;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += _value;
      emit Transfer(msg.sender, _to, _value);
      return true;
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
      allowance[msg.sender][_spender] = _value;
      return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
      require(balanceOf[_from] >= _value);
      require(allowance[_from][msg.sender] >= _value);

      balanceOf[_from] -= _value;
      balanceOf[_to] += _value;
      allowance[_from][msg.sender] -= _value;
      emit Transfer(_from, _to, _value);
      return true;
    }

    function burn(uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Callback to notify external contracts about the burn
      if (isContract(msg.sender)) {
          // solium-disable-next-line security/no-call-value
          msg.sender.call(
              abi.encodeWithSignature("onTokenBurn(uint256)", _value)
          );
          // Continue execution regardless of callback success
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      emit Burn(msg.sender, _value);
      return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
      require(balanceOf[_from] >= _value);
      require(msg.sender == owner);

      balanceOf[_from] -= _value;
      totalSupply -= _value;
      emit Burn(_from, _value);
      return true;
    }

    function isContract(address x) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(x) }
        return size > 0;
    }
}
