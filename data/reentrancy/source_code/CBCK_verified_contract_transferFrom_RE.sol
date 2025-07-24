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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a vulnerable window where:
 * 
 * 1. **Transaction 1**: Malicious contract receives tokens and can observe current allowance state through the external call
 * 2. **Transaction 2**: Malicious contract can exploit the observed state by calling transferFrom again with knowledge of the allowance that hasn't been updated yet
 * 
 * The vulnerability is stateful because:
 * - The allowance state persists between transactions
 * - Malicious contracts can accumulate information about allowance states across multiple calls
 * - The external call provides a hook for attackers to prepare multi-transaction exploits
 * 
 * This violates the checks-effects-interactions pattern by performing external calls before state updates, creating a reentrancy vulnerability that requires multiple transactions to exploit effectively. The attacker needs to first observe the system state through the external call, then execute the actual exploit in subsequent transactions.
 */
pragma solidity ^0.4.19;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Interface declaration for ITokenReceiver as required in transferFrom
interface ITokenReceiver {
    function onTokenReceived(address from, address by, uint256 value) external;
}

contract CBCK {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function CBCK(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state update creates reentrancy window
        // This allows malicious contracts to exploit the gap between allowance check and update
        if (_to != address(0) && isContract(_to)) {
            // Simulate the vulnerable external call
            ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
        }
        allowance[_from][msg.sender] -= _value;  // State update moved AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check for contract at address (Solidity v0.4.x compatible)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
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
