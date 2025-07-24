/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance state. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: The attacker must first deploy a malicious contract and get approval to spend tokens (separate transactions)
 * 
 * 2. **State Persistence**: The vulnerability exploits the persistent allowance state between transactions. The allowance remains unchanged during the external call, allowing reentrancy
 * 
 * 3. **Exploitation Sequence**:
 *    - Transaction 1: Attacker deploys malicious contract with onTokenTransfer function
 *    - Transaction 2: Token owner approves allowance for attacker
 *    - Transaction 3: Attacker calls transferFrom, triggering external call to malicious contract
 *    - During external call: Malicious contract calls transferFrom again before allowance is decremented
 *    - This allows multiple transfers using the same allowance approval
 * 
 * 4. **Realistic Integration**: The external call simulates a common pattern of notifying recipients about incoming transfers, making it appear as legitimate functionality
 * 
 * 5. **Stateful Nature**: The vulnerability depends on the allowance state persisting across the external call, and the malicious contract must be set up in advance, requiring multiple transactions to exploit effectively
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the pre-deployment of a malicious contract and the establishment of token allowances, making it genuinely multi-transaction dependent.
 */
pragma solidity ^0.4.16;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract xinfenghua{
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state update - enables reentrancy
        // This simulates a compliance check or notification system
        if (isContract(_to)) {
            // Call to potentially malicious contract before allowance is decremented
            // Need for compatibility with old Solidity: use low-level .call
            require(_to.call(bytes4(keccak256("onTokenTransfer(address,address,uint256)")), _from, _to, _value));
            // Continue execution regardless of call result to maintain functionality
        }
        // State update happens AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}
