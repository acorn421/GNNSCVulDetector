/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to notify both the old and new owners about the ownership change. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Flow:**
 * 1. **Transaction 1**: Attacker calls `changeOwner()` to set a malicious contract as `newOwner`
 * 2. **Transaction 2**: Attacker calls `acceptOwnership()` which triggers external calls to the malicious contract
 * 3. **During the external calls**: The malicious contract can re-enter and call other functions while the ownership state is being modified
 * 
 * **Specific Changes Made:**
 * - Added external calls to both old and new owners after state modification
 * - Used low-level `.call()` to avoid reverts and enable reentrancy
 * - Stored `oldOwner` before state change but made external calls after
 * - Added code length checks to only call contracts, not EOAs
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first become the `newOwner` through `changeOwner()` in a separate transaction
 * - Only after being set as `newOwner` can the attacker call `acceptOwnership()` to trigger the reentrancy
 * - The vulnerability exploits the accumulated state from the first transaction (being set as newOwner) in the second transaction
 * - The reentrancy occurs during the ownership transfer process, allowing manipulation of other contract functions while ownership is in transition
 * 
 * **Exploitation Scenario:**
 * The malicious contract can re-enter during the ownership notification callbacks to:
 * - Call `withdrawAllTokens()` while still being considered the owner
 * - Manipulate `tokensOwed` mappings through `setAmount()` 
 * - Exploit timing windows where ownership state is inconsistent
 * - Potentially drain the contract or manipulate token distributions
 * 
 * This creates a realistic vulnerability where the ownership transfer process itself becomes a reentrancy attack vector, requiring the stateful accumulation of being set as newOwner before the actual exploitation can occur.
 */
pragma solidity ^0.4.15;

contract Owned {

    /// @dev `owner` is the only address that can call a function with this
    /// modifier
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    address public owner;

    /// @notice The Constructor assigns the message sender to be `owner`
    constructor() public {
        owner = msg.sender;
    }

    address public newOwner;

    /// @notice `owner` can step down and assign some other address to this role
    /// @param _newOwner The address of the new owner. 0x0 can be used to create
    ///  an unowned neutral vault, however that cannot be undone
    function changeOwner(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        if (msg.sender == newOwner) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            address oldOwner = owner;
            owner = newOwner;
            
            // Notify old owner about ownership change
            if (oldOwner != address(0) && isContract(oldOwner)) {
                oldOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), newOwner);
            }
            
            // Notify new owner about successful ownership acceptance
            if (isContract(newOwner)) {
                newOwner.call(bytes4(keccak256("onOwnershipAccepted(address)")), oldOwner);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }

    // Helper function to check if address is a contract in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
    function balanceOf(address who) public constant returns (uint256);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Distribute is Owned {

    mapping (address => uint) public tokensOwed;
    ERC20Basic token;

    event AmountSet(address contributor, uint amount);
    event AmountSent(address contributor, uint amount);

    constructor(address _token) public {
        token = ERC20Basic(_token);
    }

    function setAmount(address contributor, uint amount) public onlyOwner {
        tokensOwed[contributor] = amount;
    }

    function withdrawAllTokens() public onlyOwner {
        token.transfer(owner, token.balanceOf(address(this)));
    }

    function() public payable {
        collect();
    }

    function collect() public {
        uint amount = tokensOwed[msg.sender];
        require(amount > 0);
        tokensOwed[msg.sender] = 0;
        token.transfer(msg.sender, amount);
        AmountSent(msg.sender, amount);
    }
}