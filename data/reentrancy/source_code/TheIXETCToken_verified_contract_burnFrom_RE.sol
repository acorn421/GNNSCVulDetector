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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates. This creates a classic reentrancy attack vector where:
 * 
 * 1. **External Call Before State Updates**: Added a call to `tokenRecipient(_from).receiveApproval()` before the critical state variables (balanceOf, allowance, totalSupply) are updated.
 * 
 * 2. **Multi-Transaction Exploitation**: An attacker can exploit this across multiple transactions:
 *    - Transaction 1: Deploy a malicious contract at address `_from` that implements `tokenRecipient`
 *    - Transaction 2: Set up allowance for the attacking contract to burn tokens
 *    - Transaction 3: Call `burnFrom` - during the external call, the malicious contract can re-enter `burnFrom` multiple times before the original state updates occur
 *    - Each re-entrant call sees the unchanged allowance and balance values, allowing unauthorized multiple burns
 * 
 * 3. **Stateful Nature**: The vulnerability requires:
 *    - Pre-existing allowance state from previous transactions
 *    - A malicious contract deployed at `_from` address
 *    - The ability to accumulate unauthorized burns across multiple re-entrant calls within a single transaction
 *    - State persistence between the setup transactions and the exploitation transaction
 * 
 * 4. **Realistic Integration**: The external call appears as a legitimate notification mechanism to inform token holders about burns, making it a subtle vulnerability that could realistically appear in production code.
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing an external call after checks but before effects, enabling classic reentrancy attacks that can drain more tokens than authorized.
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
 
contract TheIXETCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 8;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 
 
    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
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
 
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
        // Notify burn recipient before state updates (vulnerable external call)
        if (_from != msg.sender && isContract(_from)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
