/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract callers (`msg.sender != tx.origin`)
 * 2. Introduced an external call to the caller's contract with `msg.sender.call(abi.encodeWithSignature("onTokensPurchased(uint256)", amount))` 
 * 3. This call happens BEFORE the balance state updates but AFTER the amount calculation and availability check
 * 4. The external call allows the attacker's contract to re-enter the buy() function
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokensPurchased()` callback
 * 2. **Transaction 2**: Attacker's contract calls `buy()` with some ETH
 * 3. **Reentrancy Chain**: During the callback, the attacker's contract can call `buy()` again multiple times
 * 4. **State Accumulation**: Each reentrant call adds tokens to the attacker's balance before the original state updates complete
 * 5. **Persistent Effect**: The accumulated token balances persist across all reentrant calls, while only the original ETH amount is transferred
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy a malicious contract (Transaction 1)
 * - The exploitation requires the contract to then call buy() (Transaction 2)
 * - The reentrancy occurs within Transaction 2 but requires the pre-existing malicious contract state
 * - The vulnerability accumulates state changes across multiple reentrant calls within the transaction
 * - The persistent balance changes create a lasting advantage that can be exploited in subsequent transactions
 * 
 * **Realistic Nature:**
 * - The callback mechanism appears to be a legitimate feature for notifying contract buyers
 * - The vulnerability follows real-world patterns where external calls to user contracts create reentrancy vectors
 * - The code maintains all original functionality while introducing the security flaw
 * - The vulnerability is subtle and could easily be missed in code review
 */
pragma solidity ^0.4.11;

contract SwiftDex {

    string public name = "SwiftDex";      //  token name
    string public symbol = "SWIFD";           //  token symbol
    uint256 public decimals = 18;            //  token digit
    uint256 public price = 360000000000000;
    string public version="test-5.0";
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    //000000000000000000
    bool public stopped = false;
    uint256 constant decimalFactor = 1000000000000000000;

    address owner = 0x0;
    address address_ico = 0x82844C2365667561Ccbd0ceBE0043C494fE54D16;
    address address_team = 0xdB96e4AA6c08C0c8730E1497308608195Fa77B31;
    address address_extra = 0x14Eb4D0125769aC89F60A8aA52e114fAe70217Be;
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function SwiftDex () public {
        owner = msg.sender;
        totalSupply = 200000000000000000000000000;

        balanceOf[address_ico] = totalSupply * 70 / 100;
        emit Transfer(0x0, address_ico, totalSupply * 70 / 100);

        balanceOf[address_team] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_team, totalSupply * 15 / 100);

        balanceOf[address_extra] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_extra, totalSupply * 15 / 100);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function buy() public isRunning payable returns (uint amount){
        amount = msg.value * decimalFactor / price;                    // calculates the amount
        require(balanceOf[address_ico] >= amount);               // checks if it has enough to sell
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if caller is a contract and has a callback function
        if (msg.sender != tx.origin) {
            // External call to user-controlled contract before state updates
            bool success = msg.sender.call(abi.encodeWithSignature("onTokensPurchased(uint256)", amount));
            require(success, "Callback failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[address_ico] -= amount;                        // subtracts amount from seller's balance
        address_ico.transfer(msg.value);
        emit Transfer(address_ico, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function deployTokens(address[] _recipient, uint256[] _values) public isOwner {
        for(uint i = 0; i< _recipient.length; i++)
        {
              balanceOf[_recipient[i]] += _values[i] * decimalFactor;
              balanceOf[address_ico] -= _values[i] * decimalFactor;
              emit Transfer(address_ico, _recipient[i], _values[i] * decimalFactor);
        }
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setPrice(uint256 _price) public isOwner {
        price = _price;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}