/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism between balance deduction and total supply update. The vulnerability requires: 1) Transaction 1 - Attacker deploys malicious contract and sets it as burnNotificationContract, 2) Transaction 2 - Attacker calls burn() which triggers the callback, allowing reentrancy that can exploit the inconsistent state where balance is reduced but totalSupply hasn't been updated yet. The malicious callback can re-enter burn() or other functions while the contract is in an inconsistent state, potentially allowing token manipulation or balance draining across multiple calls. This violates the Checks-Effects-Interactions pattern and creates a realistic vulnerability that requires persistent state setup and sequential exploitation.
 */
pragma solidity ^0.4.16;

interface IBurnNotification {
    function onTokenBurn(address burner, uint256 value) external;
}

contract AXLToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    address public burnNotificationContract;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Axle Project";
        symbol = "AXL";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
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

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function setBurnNotificationContract(address _contract) public {
        burnNotificationContract = _contract;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External callback before completing all state updates
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onTokenBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}
