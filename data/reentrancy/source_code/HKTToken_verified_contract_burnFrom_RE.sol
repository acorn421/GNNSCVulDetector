/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that allows the token holder to receive notification when their tokens are burned. The vulnerability is created by:
 * 
 * 1. **External Call After State Updates**: An external call is made to the token holder's contract AFTER the critical state variables (balanceOf, allowance, totalSupply) have been updated, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Callback Interface Reuse**: The existing tokenRecipient interface is reused with a "BURN_NOTIFICATION" message, making this appear as a legitimate feature enhancement.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls burnFrom() for a malicious contract address
 *    - **During Callback**: The malicious contract's receiveApproval() is triggered
 *    - **Reentrancy Attack**: The malicious contract calls burnFrom() again with the same parameters
 *    - **State Inconsistency**: The second call sees updated balances but can manipulate the burn process
 *    - **Transaction 2+**: Subsequent transactions exploit the inconsistent state
 * 
 * 4. **Stateful Nature**: The vulnerability requires persistent state changes between transactions. The attacker must:
 *    - First set up allowances in separate transactions
 *    - Then exploit the callback mechanism across multiple burnFrom calls
 *    - The state modifications from each call affect subsequent calls
 * 
 * 5. **Realistic Implementation**: The try-catch pattern and callback notification appear as legitimate features that could reasonably be added to a production token contract.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the state changes to persist and be observable by subsequent external calls, making it a genuine stateful, multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);

    function HKTToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
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
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        Approval(msg.sender, _spender, _value);
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
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder about the burn via callback
        if (_from != address(0) && extcodesize(_from) > 0) {
            // No try-catch in 0.4.16, just call external contract
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    
    // Helper function for extcodesize since inline assembly is needed in 0.4.16
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
