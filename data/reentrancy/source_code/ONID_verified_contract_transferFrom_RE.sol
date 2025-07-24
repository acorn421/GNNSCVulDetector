/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before the actual transfer is completed. This creates a state inconsistency window where:
 * 
 * 1. **Transaction 1**: Initial transferFrom call reduces allowance but makes external call before _transfer completes
 * 2. **Reentrancy Window**: The external call can trigger additional transferFrom calls while the original transfer is still in progress
 * 3. **State Exploitation**: Multiple transactions can exploit the reduced allowance state before balances are actually updated
 * 
 * The vulnerability requires multiple transactions because:
 * - The allowance is decremented in the first transaction
 * - The external call creates a reentrancy opportunity where the contract state is inconsistent
 * - Additional transferFrom calls can be made during the callback, exploiting the window between allowance reduction and balance updates
 * - Each subsequent reentrant call further exploits the accumulated state changes
 * 
 * This is realistic as it mimics notification patterns seen in DeFi protocols where recipients are notified of incoming transfers, but the implementation violates the checks-effects-interactions pattern by making external calls before state is fully updated.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ONID {

    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);


    event Burn(address indexed from, uint256 value);
    uint256 initialSupply=10000000000000;
        string tokenName = "ONID";
        string tokenSymbol = "ONID";

    constructor(
        
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = tokenName;                                  
        symbol = tokenSymbol;                               
    }


    function _transfer(address _from, address _to, uint _value) internal {

        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-transaction reentrancy vulnerability: external call before state finalization
        // This creates a window where allowance is reduced but transfer hasn't completed
        if (isContract(_to)) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if an address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
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
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
