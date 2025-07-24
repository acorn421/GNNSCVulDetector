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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker approves a malicious contract with a large allowance
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls transferFrom, which triggers the external call to the malicious recipient contract
 * 3. **Reentrant Call**: The malicious contract's onTokenTransfer function re-enters transferFrom before the allowance is decremented
 * 4. **Transaction 3 (Exploitation)**: Since allowance hasn't been updated yet, the reentrant call passes the require check and can transfer tokens again
 * 5. **State Accumulation**: Multiple reentrant calls can drain more tokens than the original allowance should permit
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **State Persistence**: The allowance mapping persists between transactions, creating a window for exploitation
 * - **Sequence Dependency**: The vulnerability requires the specific sequence of approve → transferFrom → reentrant transferFrom
 * - **External Call Timing**: The external call occurs before allowance update, but the exploit relies on the allowance state being set up in previous transactions
 * - **Contract State Accumulation**: The malicious contract needs to accumulate state across multiple calls to maximize token extraction
 * 
 * **Realistic Integration**: The external call appears as a legitimate notification mechanism for smart contract recipients, making it a subtle but dangerous vulnerability commonly found in token contracts.
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
contract tokenRecipient {
     function receiveApproval(address from, uint256 value, address token, bytes extraData) public;
}
contract token {
    /*Public variables of the token */
    string public name; string public symbol; uint8 public decimals; uint256 public totalSupply;
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token() public {
    balanceOf[msg.sender] = 10000000000000000;
    totalSupply = 10000000000000000;
    name = "BCB";
    symbol =  "฿";
    decimals = 8;
    }
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);
        require (balanceOf[_from] > _value);
        require (balanceOf[_to] + _value > balanceOf[_to]);
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value < allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // WARNING: This is intentionally vulnerable for testing purposes
        if (isContract(_to)) {
            // Notify recipient contract about incoming transfer
            bool callSuccess = _to.call(bytes4(keccak256("onTokenTransfer(address,address,uint256)")), _from, _to, _value);
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
        spender.receiveApproval(msg.sender, _value, this, _extraData);
        return true;
        }
    }
    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] > _value); // Check if the sender has enough
        balanceOf[msg.sender] -= _value; // Subtract from the sender
        totalSupply -= _value; // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value); // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]); // Check allowance
        balanceOf[_from] -= _value; // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value; // Subtract from the sender's allowance
        totalSupply -= _value; // Update totalSupply
        emit Burn(_from, _value);
        return true;
      }
   }

contract BcbToken is owned, token {
    mapping (address => bool) public frozenAccount;
    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);
  


    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);
     
        require(msg.sender != _to);
        require (balanceOf[_from] > _value); // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]);
        require(!frozenAccount[_from]); // Check if sender is frozen
        require(!frozenAccount[_to]); // Check if recipient is frozen
        balanceOf[_from] -= _value; // Subtract from the sender
        balanceOf[_to] += _value; // Add the same to the recipient
        emit Transfer(_from, _to, _value);
    }

    function freezeAccount(address target, bool freeze) public onlyOwner {
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
    }
}
