/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability allows the recipient to re-enter the transfer function during the callback, enabling multiple balance deductions from the same initial balance across separate transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` signature
 * 2. Placed this external call AFTER balance validation but BEFORE state updates (violating CEI pattern)
 * 3. Added require statement to ensure call success, making the vulnerability more realistic
 * 4. Used low-level call to avoid interface requirements while maintaining realism
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 1. **Transaction 1**: Attacker calls `transfer()` with malicious contract as recipient
 * 2. **During TX1**: Balance checks pass, external call triggers attacker's `onTokenReceived` callback
 * 3. **Transaction 2 (Reentrant)**: Attacker's callback calls `transfer()` again with same parameters
 * 4. **During TX2**: Balance checks pass again (since balances haven't been updated from TX1 yet)
 * 5. **State Corruption**: Multiple balance deductions occur before any state updates complete
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the external call to trigger a reentrant call back to `transfer()`
 * - Each reentrant call must pass the initial balance checks before any state updates occur
 * - The exploit depends on the persistent state remaining unchanged between the initial call and reentrant calls
 * - Single transaction exploitation is impossible because the balance checks would fail after the first deduction
 * - The attack accumulates effects across multiple nested transaction calls, each operating on the same initial state
 * 
 * **Attack Flow:**
 * 1. Attacker deploys malicious contract with `onTokenReceived` function
 * 2. Attacker calls `transfer()` to send tokens to malicious contract
 * 3. Malicious contract's `onTokenReceived` triggers and calls `transfer()` again
 * 4. This creates multiple balance deductions from the same initial balance
 * 5. Final result: Attacker can drain more tokens than they originally had
 */
pragma solidity ^0.4.23;

contract USDT {
    mapping (address => uint256) private balances;
    mapping (address => uint256[2]) private lockedBalances;
    string public name = "USDT";                   //fancy name: eg Simon Bucks
    uint8 public decimals = 6;                //How many decimals to show.
    string public symbol = "USDT";                 //An identifier: eg SBX
    uint256 public totalSupply = 1000000000000000;
    address public owner;
        event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol,
        address _owner
    ) public {
        balances[_owner] = _initialAmount;                   // Give the owner all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
        owner = _owner;                                      // set owner
        
    }
    /*DirectDrop and AirDrop*/
    /*Checking lock limit and time limit while transfering.*/
    function transfer(address _to, uint256 _value) public returns (bool success) {
        //Before ICO finish, only own could transfer.
        if(_to != address(0)){
            if(lockedBalances[msg.sender][1] >= now) {
                require((balances[msg.sender] > lockedBalances[msg.sender][0]) &&
                 (balances[msg.sender] - lockedBalances[msg.sender][0] >= _value));
            } else {
                require(balances[msg.sender] >= _value);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // VULNERABILITY: External call to recipient before state updates
            // This allows recipient to re-enter during transfer processing
            if (isContract(_to)) {
                // Call recipient's token received callback
                (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                require(callSuccess, "Transfer notification failed");
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
    }
    /*With permission, destory token from an address and minus total amount.*/
    function burnFrom(address _who,uint256 _value)public returns (bool){
        require(msg.sender == owner);
        assert(balances[_who] >= _value);
        totalSupply -= _value;
        balances[_who] -= _value;
        lockedBalances[_who][0] = 0;
        lockedBalances[_who][1] = 0;
        return true;
    }
    /*With permission, creating coin.*/
    function makeCoin(uint256 _value)public returns (bool){
        require(msg.sender == owner);
        totalSupply += _value;
        balances[owner] += _value;
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
    /*With permission, withdraw ETH to owner address from smart contract.*/
    function withdraw() public{
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
    /*With permission, withdraw ETH to an address from smart contract.*/
    function withdrawTo(address _to) public{
        require(msg.sender == owner);
        address(_to).transfer(address(this).balance);
    }
    // Helper function to check if target address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
