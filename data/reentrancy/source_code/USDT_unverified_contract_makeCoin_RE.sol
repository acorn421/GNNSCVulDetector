/*
 * ===== SmartInject Injection Details =====
 * Function      : makeCoin
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a price oracle contract after state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Owner calls makeCoin(1000), state is updated (totalSupply += 1000, balances[owner] += 1000)
 * 2. **External Call**: Contract calls priceOracle.updateSupply() which can reenter makeCoin()
 * 3. **Reentrant Calls**: Oracle contract (controlled by attacker or compromised) calls makeCoin() multiple times before original call completes
 * 4. **State Accumulation**: Each reentrant call adds to totalSupply and owner balance
 * 5. **Result**: Total supply and owner balance inflated far beyond intended single mint amount
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on accumulated state changes across multiple reentrant calls
 * - Each reentrant call builds upon the state modifications from previous calls
 * - The exploit cannot be achieved in a single transaction without the external call trigger
 * - The state persistence between calls (totalSupply and balances) enables the compounding effect
 * 
 * **Realistic Attack Scenario:**
 * - Owner calls makeCoin(1000) intending to mint 1000 tokens
 * - Price oracle contract is compromised or malicious
 * - Oracle's updateSupply() function reenters makeCoin() 10 times with value 1000
 * - Final result: 11,000 tokens minted instead of 1000 (1 original + 10 reentrant calls)
 * - State changes persist across all reentrant calls, creating compounding effect
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by placing the external call after state modifications, enabling reentrancy that can exploit the accumulated state changes.
 */
pragma solidity ^0.4.23;

interface IPriceOracle {
    function updateSupply(uint256 newTotalSupply, uint256 mintedAmount) external;
}

contract USDT {
    mapping (address => uint256) private balances;
    mapping (address => uint256[2]) private lockedBalances;
    string public name = "USDT";                   //fancy name: eg Simon Bucks
    uint8 public decimals = 6;                //How many decimals to show.
    string public symbol = "USDT";                 //An identifier: eg SBX
    uint256 public totalSupply = 1000000000000000;
    address public owner;
    address public priceOracle;
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
        priceOracle = address(0);                            // initialize priceOracle as zero address
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external price oracle about supply change
        if(priceOracle != address(0)) {
            IPriceOracle(priceOracle).updateSupply(totalSupply, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
