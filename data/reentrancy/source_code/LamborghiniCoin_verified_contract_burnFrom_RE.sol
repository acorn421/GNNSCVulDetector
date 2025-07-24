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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_from.call(payload)` that invokes `onTokenBurn` on the token holder's address
 * 2. This call occurs BEFORE state variables (balanceOf, allowance, totalSupply) are updated
 * 3. The call is only made when `_from != msg.sender` to maintain realistic functionality
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * Transaction 1: Attacker calls burnFrom, triggering the external call to their malicious contract
 * Transaction 2+: The malicious contract's onTokenBurn function calls burnFrom again, exploiting the unchanged state
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability depends on the external call triggering subsequent burnFrom calls while the original call's state changes are still pending
 * - The attacker needs to set up their malicious contract beforehand (separate transaction)
 * - The exploit requires the malicious contract to make additional burnFrom calls during the callback
 * - State accumulation across transactions allows the attacker to burn more tokens than they should be able to
 * - The allowance and balance checks pass on reentrant calls because state hasn't been updated yet
 * 
 * **Realistic Implementation:**
 * - The callback mechanism appears legitimate (notifying token holders about burns)
 * - The conditional check (_from != msg.sender) makes it seem like a reasonable optimization
 * - The vulnerability is subtle and could easily pass code review
 * - Follows real-world patterns seen in DeFi protocols that notify users about token operations
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract LamborghiniCoin {
    string public name = "Lamborghini Official Coin"; //Implemented by Nando AEC 2018-05-22
    string public symbol = "LOCC";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    constructor(
                ) public {
        totalSupply = 200000000 * 10 ** uint256(18);  
        balanceOf[msg.sender] = totalSupply;         
        name = "Lamborghini Official Coin";           
        symbol = "LOCC";                               
    }

    /**
     * Internal transfer, only can be called by this contract
     */
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
        
        // Notify token holder about the burn operation before state changes
        if (_from != msg.sender) {
            // External call to user-controlled contract before state updates
            bytes memory payload = abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value);
            _from.call(payload);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                        
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                             
        emit Burn(_from, _value);
        return true;
    }
}