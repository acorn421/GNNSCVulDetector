/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending burns tracking mechanism and external burn hook callback. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingBurns[_from] += _value` to track accumulated burn amounts across transactions
 * 2. Introduced external call `IBurnHook(burnHook).onBurnInitiated(_from, _value, pendingBurns[_from])` before state updates
 * 3. State updates (`balanceOf[_from] -= _value; totalSupply -= _value`) occur after the external call
 * 4. Added `pendingBurns[_from] = 0` reset after successful burn
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `burnFrom(victim, 100)` - this adds 100 to `pendingBurns[victim]` and calls the external hook
 * 2. **Malicious Hook**: The hook can see `pendingBurns[victim] = 100` and call back into other contract functions or external contracts
 * 3. **Transaction 2**: Before the first burn completes, owner calls `burnFrom(victim, 50)` - this adds 50 to existing pending burns (`pendingBurns[victim] = 150`)
 * 4. **Exploitation**: The hook now sees accumulated pending burns of 150 and can exploit this state inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the accumulated state in `pendingBurns` mapping that persists between transactions
 * - A single transaction would not build up sufficient pending burn state to exploit
 * - The hook needs to observe the accumulated pending burns across multiple calls to manipulate external state or trigger callbacks
 * - The exploit becomes effective when multiple burns are pending simultaneously, creating state inconsistencies
 * 
 * **Attack Vector:**
 * - Malicious burn hook could use the accumulated pending burn information to manipulate external DeFi protocols, oracles, or governance systems
 * - The hook could call back into the token contract or other contracts while the state is inconsistent
 * - Multiple pending burns create a window where the hook can exploit the gap between external calls and state updates
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

    // Added storage for the vulnerability logic
    mapping (address => uint256) public pendingBurns;
    address public burnHook;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // Moved IBurnHook interface outside contract as per Solidity 0.4.x requirements
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
      Transfer(msg.sender, _to, _value);
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
      Transfer(_from, _to, _value);
      return true;
    }

    function burn(uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      Burn(msg.sender, _value);
      return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
      require(balanceOf[_from] >= _value);
      require(msg.sender == owner);

      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Add to pending burns for batch processing
      pendingBurns[_from] += _value;

      // Notify external burn hook before state updates
      if (burnHook != address(0)) {
          IBurnHook(burnHook).onBurnInitiated(_from, _value, pendingBurns[_from]);
      }

      // State updates occur after external call
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balanceOf[_from] -= _value;
      totalSupply -= _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

      // Reset pending burns after successful burn
      pendingBurns[_from] = 0;

      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      Burn(_from, _value);
      return true;
    }
}

// Moved outside the main contract
interface IBurnHook {
    function onBurnInitiated(address from, uint256 value, uint256 totalPending) external;
}
