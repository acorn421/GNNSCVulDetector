/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating the allowance state. This creates a window where the contract can be re-entered with the original allowance still intact, allowing multiple transfers to be executed with the same allowance across different transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `ITransferNotification(_to).onTokenTransfer()` before the allowance is decremented
 * 2. Used `_to.code.length > 0` to check if the recipient is a contract
 * 3. Wrapped the external call in a try-catch to maintain functionality if the recipient doesn't implement the interface
 * 4. The external call passes current balance information, making it realistic for notification purposes
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker approves a malicious contract with allowance of 1000 tokens
 * 2. **Transaction 2**: Legitimate user calls transferFrom(attacker, maliciousContract, 500)
 * 3. **During Transaction 2**: The malicious contract's onTokenTransfer is called BEFORE allowance is decremented
 * 4. **Reentrancy**: The malicious contract immediately calls transferFrom again with the same allowance
 * 5. **Transaction 3**: The reentrant call succeeds because allowance[attacker][user] is still 1000 (not yet decremented)
 * 6. **Result**: 1000 tokens transferred using only 500 allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires an initial approval transaction to set up the allowance
 * - The exploitation depends on the specific state of allowances at the time of the external call
 * - The attacker needs to deploy a malicious contract that implements the notification interface
 * - The reentrancy attack spans multiple call frames within the same transaction, but the setup requires multiple transactions
 * - The vulnerability accumulates over multiple transferFrom calls where the allowance isn't properly decremented due to reentrancy
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent allowance mapping state
 * - Each failed reentrancy attempt still consumes the allowance incorrectly
 * - The attack can be repeated across multiple transactions until the allowance is exhausted
 * - The contract's state becomes inconsistent between the allowance and actual token balances
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Added ITransferNotification interface to fix error
interface ITransferNotification {
    function onTokenTransfer(address _from, uint256 _value, uint256 _balance) external;
}

contract DoosToken {
    string public name = 'DOOS';
    string public symbol = 'DOOS';
    uint8 public decimals = 18;
    uint256 public totalSupply = 10000000;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function DoosToken(
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
        
        // External call to notify recipient before state updates
        if (isContract(_to)) {
            ITransferNotification(_to).onTokenTransfer(_from, _value, balanceOf[_from]);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Utility function for detecting contracts (for pre-0.5.0 Solidity)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
