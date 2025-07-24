/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack through the following mechanism:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `IBurnNotification(_from).onBurnNotification(_value, totalSupply)` after the require statements but before state updates
 * 2. The external call passes the current totalSupply value, creating a window where state is inconsistent
 * 3. Added a check `if(_from.code.length > 0)` to only call contracts, making it realistic
 * 
 * **Multi-Transaction Exploitation Path:**
 * Transaction 1 (Setup): Attacker deploys a malicious contract that implements IBurnNotification
 * Transaction 2 (Initial Burn): Owner calls burnFrom on the malicious contract address
 * - The malicious contract's onBurnNotification is called with current totalSupply
 * - During this callback, the malicious contract can call other functions that depend on totalSupply
 * - State variables (balanceOf, totalSupply) haven't been updated yet, creating inconsistency
 * Transaction 3+ (Exploit): The malicious contract can leverage the state inconsistency to perform additional actions
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. The attacker must first deploy a malicious contract implementing IBurnNotification (Transaction 1)
 * 2. The owner must call burnFrom on the malicious contract (Transaction 2)
 * 3. The vulnerability depends on the accumulated state changes and requires the malicious contract to be already deployed and positioned
 * 4. The exploit leverages the fact that totalSupply and balanceOf values are stale during the external call, requiring prior state setup
 * 
 * **State Persistence Aspect:**
 * - The vulnerability depends on the persistent state variables (balanceOf, totalSupply)
 * - The attack requires the malicious contract to be deployed and ready to receive the callback
 * - The state inconsistency window allows the malicious contract to make decisions based on stale totalSupply values while balanceOf hasn't been updated yet
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to set up and exploit, making it a perfect example of a stateful, multi-transaction security flaw.
 */
pragma solidity ^0.4.13;

// Interface declaration for IBurnNotification
interface IBurnNotification {
    function onBurnNotification(uint256 _value, uint256 _totalSupply) external;
}

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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

      // Notify the affected address before state update (vulnerable external call)
      if(isContract(_from)) {
          // This creates a reentrancy window where state hasn't been updated yet
          IBurnNotification(_from).onBurnNotification(_value, totalSupply);
      }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

      balanceOf[_from] -= _value;
      totalSupply -= _value;
      emit Burn(_from, _value);
      return true;
    }

    // Helper for contract detection compatible with Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
