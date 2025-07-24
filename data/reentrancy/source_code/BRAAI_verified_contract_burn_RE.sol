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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to governance and listener contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements the burn listener interface
 * 2. **Transaction 2**: Attacker calls burn() with a value that triggers the external call to their malicious listener contract
 * 3. **During Transaction 2**: The malicious listener contract receives the onTokenBurn callback and immediately calls burn() again before the original call completes its state updates
 * 4. **Exploitation**: The reentrant call sees the original balance (not yet decremented) and can burn more tokens than the attacker actually holds
 * 
 * **Why Multi-Transaction:**
 * - Transaction 1 is needed to set up the malicious listener contract
 * - Transaction 2 triggers the vulnerability but requires the pre-existing malicious contract
 * - The vulnerability exploits the window between balance checks and balance updates across the reentrant calls
 * - State persistence between transactions enables the attack setup
 * 
 * **Stateful Nature:**
 * - The attacker's malicious contract must be deployed and ready to receive callbacks
 * - The vulnerability depends on the persistent state of balanceOf and totalSupply
 * - Each reentrant call can drain more tokens, creating cumulative damage across the nested calls
 * - The exploit creates lasting state inconsistencies that persist after the transaction completes
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BRAAI {

    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);


    event Burn(address indexed from, uint256 value);
    uint256 initialSupply=120000000;
        string tokenName = "BRAAI";
        string tokenSymbol = "BRAAI";

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if this is a large burn that requires governance approval
        if (_value > totalSupply / 100) { // Burns > 1% of total supply
            // Call governance contract to check approval status
            // This external call occurs before state updates
            address governanceContract = 0x1234567890123456789012345678901234567890;
            if (governanceContract.call(bytes4(keccak256("checkBurnApproval(address,uint256)")), msg.sender, _value)) {
                // If governance approves, continue with burn
            } else {
                revert("Large burn requires governance approval");
            }
        }
        
        // Notify external burn listeners before state changes
        // This creates a reentrancy opportunity
        address burnListener = 0x9876543210987654321098765432109876543210;
        if (burnListener.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value)) {
            // External notification sent
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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