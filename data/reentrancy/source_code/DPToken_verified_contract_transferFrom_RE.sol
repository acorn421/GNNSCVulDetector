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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **First Transaction**: Attacker sets up allowance and deploys malicious contract
 * 2. **Second Transaction**: Calls transferFrom which triggers the external call to the malicious recipient
 * 3. **Reentrancy Attack**: During the receiveApproval callback, the malicious contract can re-enter transferFrom since the allowance hasn't been decremented yet
 * 4. **State Exploitation**: The attacker can drain more tokens than allowed by exploiting the unchanged allowance state
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker must first obtain allowance approval (transaction 1)
 * - Then trigger the vulnerable transferFrom call (transaction 2)
 * - The exploit leverages the persistent allowance state that accumulates across transactions
 * - Each reentrant call can exploit the same allowance amount until it's finally decremented
 * 
 * This mirrors real-world token vulnerabilities where notification mechanisms create reentrancy opportunities that can be exploited through accumulated allowance state.
 */
pragma solidity ^0.4.19;

interface tokenRecipients3dp { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract DPToken {
    string public name = "3DP-Token";
    string public symbol = "3DP";
    uint8 public decimals = 2;
    uint256 public totalSupply = 30000000000;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function DPToken(
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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before state changes - vulnerable to reentrancy
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            tokenRecipients3dp(_to).receiveApproval(_from, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipients3dp spender = tokenRecipients3dp(_spender);
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
