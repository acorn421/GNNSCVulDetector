/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase ownership transfer process. The vulnerability requires:
 * 
 * 1. **State Accumulation**: Added `pendingOwner` and `transferInitiated` state variables that persist between transactions
 * 2. **Multi-Transaction Requirement**: First transaction initiates transfer, second transaction completes it
 * 3. **Reentrancy Points**: External calls are made before critical state updates in both phases
 * 4. **Exploitation Window**: During the external calls, the contract state can be manipulated through reentrancy
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: Current owner calls transferOwnership(attackerContract) - sets pendingOwner and transferInitiated
 * - During the external call in phase 1, attackerContract can reenter and call other functions while transfer is in progress
 * - Transaction 2: Owner calls transferOwnership(attackerContract) again to complete transfer
 * - During the external call in phase 2, attackerContract can reenter before final state changes occur
 * - The attacker can manipulate contract state during these windows, potentially accessing owner-only functions or disrupting the transfer process
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability spans two distinct transactions due to the two-phase design
 * - State from transaction 1 (pendingOwner, transferInitiated) is required for transaction 2
 * - Single transaction cannot exploit both phases simultaneously
 * - The reentrancy opportunities exist across the transaction boundary, requiring persistent state manipulation
 */
pragma solidity ^0.4.18;


contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  
 
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  address public pendingOwner;
  bool private transferInitiated;

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    
    if (!transferInitiated) {
      // First phase: initiate transfer
      pendingOwner = newOwner;
      transferInitiated = true;
      
      // External call to notify stakeholders - VULNERABLE TO REENTRANCY
      if (newOwner.callcode(bytes4(0))) {} // Placeholder to avoid empty if; see next line for real check (Solidity <0.5.0 workaround)
      if (extcodesize(newOwner) > 0) {
        // extcodesize is used instead of newOwner.code.length in <0.5.0
        bool successInit;
        successInit = newOwner.call(abi.encodeWithSignature("onOwnershipTransferInitiated(address)", owner));
        // Continue regardless of success
      }
      
      return;
    } else {
      // Second phase: complete transfer
      require(pendingOwner == newOwner);
      
      // External call before state change - REENTRANCY VULNERABILITY
      if (extcodesize(newOwner) > 0) {
        bool successComp;
        successComp = newOwner.call(abi.encodeWithSignature("onOwnershipTransferCompleted(address)", owner));
        // Continue regardless of success
      }
      
      // State changes after external call - VULNERABLE
      emit OwnershipTransferred(owner, newOwner);
      owner = newOwner;
      pendingOwner = address(0);
      transferInitiated = false;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
  
  function extcodesize(address _addr) internal view returns (uint256 size) {
    assembly { size := extcodesize(_addr) }
  }

}


interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BING is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);


    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol) 
        public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;           
        name = tokenName;                           
        symbol = tokenSymbol; }


    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances); }


    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value); }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true; }


    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true; }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true; } }


    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                  
        emit Burn(msg.sender, _value);
        return true; }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);  
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;         
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true; }
}
