/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the deposit function. The vulnerability occurs through:
 * 
 * 1. **State Tracking**: Added mappings to track user balances, deposit counts, and timestamps that persist between transactions
 * 2. **External Callback**: Added an external call to notify the depositor about their deposit via onDeposit() callback
 * 3. **Critical State Updates After External Call**: Moved key state updates (totalDeposits, lastDepositTime, bonus application) to occur AFTER the external call
 * 4. **Multi-Transaction Dependency**: The vulnerability requires multiple deposits to accumulate userDepositCount >= 5 to trigger the bonus logic
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - Transaction 1-4: User deposits funds normally to build up userDepositCount
 * - Transaction 5+: User deploys a malicious contract that implements onDeposit() callback
 * - When the 5th deposit is made, the callback is triggered before totalDeposits is updated
 * - The malicious contract can re-enter deposit() seeing stale totalDeposits value
 * - Each re-entrant call sees the old state and can manipulate bonus calculations
 * - The accumulated state from previous transactions enables this exploitation pattern
 * 
 * **Why Multi-Transaction**: The vulnerability specifically requires building up userDepositCount through multiple prior deposits to reach the bonus threshold, making it inherently multi-transaction dependent. Single-transaction exploitation is impossible since the deposit count starts at 0.
 */
pragma solidity ^0.4.25;

/**
 * EtherDice - fully transparent and decentralized betting
 *
 * Web              - https://etherdice.biz
 * Telegram chat    - https://t.me/EtherDice
 * Telegram channel - https://t.me/EtherDiceInfo
 *
 * Recommended gas limit: 200000
 * Recommended gas price: https://ethgasstation.info/
 */
contract EtherDice {
    
    address public constant OWNER = 0x8026F25c6f898b4afE03d05F87e6c2AFeaaC3a3D;
    address public constant MANAGER = 0xD25BD6c44D6cF3C0358AB30ed5E89F2090409a79;
    uint constant public FEE_PERCENT = 2;
    
    uint public minBet;
    uint public maxBet;
    uint public currentIndex;
    uint public lockBalance;
    uint public betsOfBlock;
    uint entropy;
    
    struct Bet {
        address player;
        uint deposit;
        uint block;
    }

    Bet[] public bets;

    event PlaceBet(uint num, address player, uint bet, uint payout, uint roll, uint time);

    // Modifier on methods invokable only by contract owner and manager
    modifier onlyOwner {
        require(OWNER == msg.sender || MANAGER == msg.sender);
        _;
    }

    // This function called every time anyone sends a transaction to this contract
    function() public payable {
        if (msg.value > 0) {
            createBet(msg.sender, msg.value);
        }
        
        placeBets();
    }
    
    // Records a new bet to the public storage
    function createBet(address _player, uint _deposit) internal {
        
        require(_deposit >= minBet && _deposit <= maxBet); // check deposit limits
        
        uint lastBlock = bets.length > 0 ? bets[bets.length-1].block : 0;
        
        require(block.number != lastBlock || betsOfBlock < 50); // maximum 50 bets per block
        
        uint fee = _deposit * FEE_PERCENT / 100;
        uint betAmount = _deposit - fee; 
        
        require(betAmount * 2 + fee <= address(this).balance - lockBalance); // profit check
        
        sendOwner(fee);
        
        betsOfBlock = block.number != lastBlock ? 1 : betsOfBlock + 1;
        lockBalance += betAmount * 2;
        bets.push(Bet(_player, _deposit, block.number));
    }

    // process all the bets of previous players
    function placeBets() internal {
        
        for (uint i = currentIndex; i < bets.length; i++) {
            
            Bet memory bet = bets[i];
            
            if (bet.block < block.number) {
                
                uint betAmount = bet.deposit - bet.deposit * FEE_PERCENT / 100;
                lockBalance -= betAmount * 2;

                // Bets made more than 256 blocks ago are considered failed - this has to do
                // with EVM limitations on block hashes that are queryable 
                if (block.number - bet.block <= 256) {
                    entropy = uint(keccak256(abi.encodePacked(blockhash(bet.block), entropy)));
                    uint roll = entropy % 100 + 1;
                    uint payout = roll < 50 ? betAmount * 2 : 0;
                    send(bet.player, payout);
                    emit PlaceBet(i + 1, bet.player, bet.deposit, payout, roll, now); 
                }
            } else {
                break;
            }
        }
        
        currentIndex = i;
    }
    
    // Safely sends the ETH by the passed parameters
    function send(address _receiver, uint _amount) internal {
        if (_amount > 0 && _receiver != address(0)) {
            _receiver.send(_amount);
        }
    }
    
    // Sends funds to the owner and manager
    function sendOwner(uint _amount) internal {
        send(OWNER, _amount * 7 / 10);
        send(MANAGER, _amount * 3 / 10);
    }
    
    // Funds withdrawal
    function withdraw(uint _amount) public onlyOwner {
        require(_amount <= address(this).balance - lockBalance);
        sendOwner(_amount);
    }
    
    // Set limits for deposits
    function configure(uint _minBet, uint _maxBet) onlyOwner public {
        require(_minBet >= 0.001 ether && _minBet <= _maxBet);
        minBet = _minBet;
        maxBet = _maxBet;
    }

    // This function deliberately left empty. It's primary use case is to top up the bank roll
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint) public userBalances;
    mapping(address => uint) public userDepositCount;
    mapping(address => uint) public lastDepositTime;
    uint public totalDeposits;

    function deposit() public payable {
        require(msg.value > 0, "Deposit must be greater than 0");
        
        // Update user balance first
        userBalances[msg.sender] += msg.value;
        userDepositCount[msg.sender] += 1;
        
        // Calculate potential bonus for frequent depositors
        uint bonus = 0;
        if (userDepositCount[msg.sender] >= 5) {
            bonus = msg.value * 5 / 100; // 5% bonus for frequent depositors
        }
        
        // External call to notify depositor about their deposit (potential callback)
        // SOLIDITY <0.5.0: No .code member. Use extcodesize.
        uint codeLength;
        address sender = msg.sender;
        assembly { codeLength := extcodesize(sender) }
        if (codeLength > 0) {
            sender.call(
                abi.encodeWithSignature("onDeposit(uint256,uint256)", msg.value, bonus)
            );
            // Continue even if callback fails
        }
        
        // State updates after external call - VULNERABLE TO REENTRANCY
        totalDeposits += msg.value;
        lastDepositTime[msg.sender] = block.timestamp;
        
        // Apply bonus after external call
        if (bonus > 0 && address(this).balance >= bonus) {
            userBalances[msg.sender] += bonus;
            msg.sender.transfer(bonus);
        }
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    // Returns the number of bets created
    function totalBets() public view returns(uint) {
        return bets.length;
    }
}
