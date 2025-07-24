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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Updates**: Added a callback to `_from` address before state modifications, violating the checks-effects-interactions pattern
 * 2. **State Persistence**: The vulnerability exploits the fact that allowance and balance state persists between transactions
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker (as approved spender) calls burnFrom with malicious contract as _from
 *    - During external call: Malicious contract reenters burnFrom before state updates complete
 *    - The reentrant call sees original allowance values and can burn additional tokens
 *    - Transaction 2+: Further exploitation possible due to corrupted state between allowance and actual burns
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction establishes the allowance that enables the attack
 * - Reentrant calls during burn processing can exploit stale state
 * - Accumulated state corruption across calls enables continued exploitation
 * - The attacker needs to have prior approval setup (separate transaction) to execute the attack
 * 
 * This creates a realistic scenario where an approved spender can burn more tokens than their allowance permits through careful timing of reentrant calls.
 */
pragma solidity ^0.4.16;
/**
 * B2AND Token contract
 *
 * The final version 2018-02-18
 */
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
contract Ownable {
    address public owner;
    constructor() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}
contract B2ANDcoin is Ownable {
    string public name;
    string public symbol;
    uint8 public decimals = 18;   
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    constructor() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = "B2ANDcoin";                                
        symbol = "B2C";                  
    }
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);    
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
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
        require(_value <= allowance[_from][msg.sender]);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Emit burn event and notify token holder before state updates
        emit Burn(_from, _value);
        
        // Call external contract to notify about the burn (vulnerability injection point)
        // Minimal fix: check if _from is a contract via extcodesize
        uint256 size;
        assembly { size := extcodesize(_from) }
        if (size > 0) {
            // This external call happens before state updates - classic reentrancy pattern
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of external call result
        }
        
        // State updates happen AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
}
