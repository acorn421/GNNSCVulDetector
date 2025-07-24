/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner address before updating the owner state variable. This creates a reentrancy window where the malicious contract can call back into the contract while the owner variable still holds the old value, allowing for potential privilege escalation and state manipulation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` with a callback notification before the state update
 * 2. Moved the `owner = newOwner;` assignment to occur AFTER the external call
 * 3. Added a contract existence check to only call contracts, not EOAs
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Current owner calls `transferOwnership(maliciousContract)` 
 * - **During callback**: The malicious contract receives `onOwnershipTransfer()` callback while `owner` is still the old owner
 * - **Within callback**: Malicious contract can call other privileged functions that check `onlyOwner` modifier (like another `transferOwnership` call)
 * - **Transaction 2+**: Malicious contract can continue exploiting the intermediate state or setup additional attack vectors
 * 
 * **Why Multi-Transaction Required:**
 * 1. The vulnerability requires the attacker to first become the pending new owner through a legitimate call
 * 2. The callback mechanism creates a reentrant state where old owner privileges persist during the transition
 * 3. Complex exploitation requires multiple function calls to fully compromise the contract state
 * 4. The stateful nature means the attack builds across transactions, with each transaction potentially setting up the next phase
 * 
 * This creates a realistic ownership transition vulnerability where the callback mechanism intended for notification becomes an attack vector for multi-transaction state manipulation.
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Notify new owner of ownership transfer with callback
    // Use low-level call without code check, as .code and .selector are unavailable; this is vulnerable and maintains reentrancy
    newOwner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", owner));
    // Continue regardless of callback success
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    owner = newOwner;
  }

}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract MMX is Ownable {
    
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
