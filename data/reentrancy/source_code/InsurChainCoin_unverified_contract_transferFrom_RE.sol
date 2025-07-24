/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state changes. The vulnerability allows recipient contracts to call back into the token contract during the notification callback, enabling multi-transaction exploitation patterns:
 * 
 * **Changes Made:**
 * 1. Added an external call to recipient contract using `_to.call()` after all state updates
 * 2. The call attempts to invoke `onTokenReceived()` callback on the recipient contract
 * 3. This creates a reentrancy window where the recipient can perform additional operations
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker contract calls `transferFrom()` with itself as recipient
 * 2. During the `onTokenReceived()` callback, the attacker contract calls `approve()` to increase allowance for itself
 * 3. **Transaction 2**: Attacker exploits the increased allowance to transfer additional tokens
 * 4. The vulnerability accumulates through state persistence between transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance increase in Transaction 1 persists in contract state
 * - Transaction 2 exploits this accumulated state to transfer more tokens than originally approved
 * - Single-transaction exploitation is limited by the original allowance check
 * - The persistent state changes (balances, allowances) enable escalating attacks across multiple transactions
 * 
 * This creates a realistic vulnerability where the external call enables state manipulation across transaction boundaries, making it a genuine multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.13;

contract InsurChainCoin {
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
      owner = 0xf1A67c1a35737fb93fBC6F5e7d175cFBfCe3aD09;
      name = 'InsurChain Coin';
      symbol = 'INSUR';
      decimals = 18;
      totalSupply = 20000000000000000000000000000;  // 2 billion
      balanceOf[owner] = 20000000000000000000000000000;
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify recipient contract about the transfer
      uint codeLength;
      assembly { codeLength := extcodesize(_to) }
      if (codeLength > 0) {
          _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      return true;
    }

    function burn(uint256 _value) public returns (bool success) {
      require(balanceOf[msg.sender] >= _value);

      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
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
}
