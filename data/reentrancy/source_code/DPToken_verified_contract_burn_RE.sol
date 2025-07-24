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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn reward contract that executes BETWEEN balance reduction and totalSupply update. This creates a critical window where state is inconsistent across transactions. The vulnerability requires multiple transactions to exploit: 1) Initial burn setup/reward contract deployment, 2) First burn call that triggers reentrancy, 3) Subsequent reentrant calls that exploit the inconsistent state where user balance is reduced but totalSupply is not yet updated, allowing manipulation of token economics across multiple transactions.
 */
pragma solidity ^0.4.19;

interface tokenRecipients3dp{ function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface BurnRewardInterface {
    function onBurn(address burner, uint256 value) external;
}

contract DPToken{
  string public name = "3DP-Token";
  string public symbol = "3DP";
  uint8 public  decimals = 2;
  uint256 public totalSupply=30000000000;
  
  mapping (address => uint256) public balanceOf;
  mapping (address => mapping (address => uint256)) public allowance;
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Burn(address indexed from, uint256 value);
  
  address public burnRewardContract;

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 30000000000;  
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;                   
        symbol = tokenSymbol;               
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
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
        tokenRecipients3dp spender = tokenRecipients3dp(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        balanceOf[msg.sender] -= _value;
        
        // Reward system for burning tokens - external call before totalSupply update
        if (burnRewardContract != address(0)) {
            BurnRewardInterface(burnRewardContract).onBurn(msg.sender, _value);
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
