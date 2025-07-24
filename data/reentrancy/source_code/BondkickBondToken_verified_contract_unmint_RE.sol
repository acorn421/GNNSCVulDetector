/*
 * ===== SmartInject Injection Details =====
 * Function      : unmint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to an audit contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Setup Transaction**: The attacker must first configure their audit contract address in the `auditSystem` mapping (requiring a separate contract or function call)
 * 
 * 2. **Exploitation Transaction**: When unmint is called, the external audit contract call occurs before state changes, creating a reentrancy window
 * 
 * 3. **Multi-Transaction Exploitation**: The audit contract can reenter unmint multiple times within the same transaction, but the real vulnerability emerges across multiple transactions where accumulated state inconsistencies allow the attacker to:
 *    - Manipulate balances across transaction boundaries
 *    - Create discrepancies between totalSupply and actual token distribution
 *    - Execute partial unmints that leave the contract in inconsistent states
 * 
 * The vulnerability violates the checks-effects-interactions pattern by placing the external call before state modifications, and requires the prerequisite state (audit contract registration) to be set up in previous transactions, making it truly multi-transaction dependent.
 */
pragma solidity ^0.4.16;

contract ERC20 {

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowance;

    function transfer(address to, uint256 value) returns (bool success);

    function transferFrom(address from, address to, uint256 value) returns (bool success);

    function approve(address spender, uint256 value) returns (bool success);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

interface IAuditContract {
    function notifyUnmint(address sender, uint256 value) public returns (bool);
}

contract BondkickBondToken is ERC20 {

    string public name;
    string public symbol;
    uint8 public decimals;

    address public owner;
    
    // Added auditSystem mapping as implied by usage in unmint
    mapping(address => address) public auditSystem;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    constructor(string _name, string _symbol, uint8 _decimals, uint256 _initialMint) public {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        owner = msg.sender;
        
        if (_initialMint > 0) {
            totalSupply += _initialMint;
            balanceOf[msg.sender] += _initialMint;
                        
            Transfer(address(0), msg.sender, _initialMint);
        }
    }

    function transfer(address _to, uint256 _value) returns (bool success) {
        require(_to != address(0));
        require(balanceOf[msg.sender] >= _value);
        
        _transfer(msg.sender, _to, _value);
        
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(_to != address(0));
        require(balanceOf[_from] >= _value);
        require(allowance[_from][msg.sender] >= _value);
        
        allowance[_from][msg.sender] -= _value;
        
        _transfer(_from, _to, _value);
        
        return true;
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        require(_spender != address(0));

        allowance[msg.sender][_spender] = _value;

        Approval(msg.sender, _spender, _value);
        
        return true;
    }

    function mint(uint256 _value) onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[msg.sender] += _value;
                    
        Transfer(address(0), msg.sender, _value);
        
        return true;
    }
    
    function mintTo (uint256 _value, address _to) onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[_to] += _value;
        
        Transfer(address(0), _to, _value);
        
        return true;
    }

    function unmint(uint256 _value) onlyOwner returns (bool success) {
        require(_value > 0 && balanceOf[msg.sender] >= _value);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify external audit contract before state changes
        address auditContract = auditSystem[msg.sender];
        if (auditContract != address(0)) {
            // External call before state update - creates reentrancy window
            bool auditResult = IAuditContract(auditContract).notifyUnmint(msg.sender, _value);
            require(auditResult);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        totalSupply -= _value;
        balanceOf[msg.sender] -= _value;

        Transfer(msg.sender, address(0), _value);

        return true;
    }
    
    function changeOwner(address _newOwner) onlyOwner returns (bool success) {
        require(_newOwner != address(0));

        owner = _newOwner;
        
        return true;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);
    }
}
