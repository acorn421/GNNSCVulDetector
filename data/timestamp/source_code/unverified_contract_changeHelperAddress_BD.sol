/*
 * ===== SmartInject Injection Details =====
 * Function      : changeHelperAddress
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls to exploit. The vulnerability includes: 1) Time-based access control using block.timestamp for business hours validation, 2) Cooldown enforcement storing last change time in state, 3) Two-phase commit process requiring proposal and execution in separate transactions with time delays. This creates multiple exploitation vectors: miners can manipulate timestamps to bypass time restrictions, attackers can exploit timing windows across transactions, and the stateful nature allows for accumulated timing-based attacks across multiple blocks.
 */
pragma solidity ^0.4.21;

contract TrumpMugz {
    address owner;
    address helper = 0xd461f698B8bFaD15f7493264208e6884Bac73997;

    // New state variables
    address public topBuyer = address(0); // Initialize to zero address
    uint256 public topPurchase = 0;       // Initialize to zero

    uint256 public TimeFinish = 0;
    uint256 TimerResetTime = 7200;
    uint256 TimerStartTime = 360000;
    uint256 public Pot = 0;
    uint16 PIncr = 10000;
    uint16 DIVP = 10000;
    uint16 POTP = 0;
    uint16 WPOTPART = 9000;

    uint16 public DEVP = 500;
    uint16 public HVAL = 2500;
    uint256 BasicPrice = .03 ether;

    // ===== Fixed for Helper proposal variables =====
    uint256 public lastHelperChangeTime = 0;
    address public proposedHelper = address(0);
    uint256 public proposalTimestamp = 0;
    // ==============================================

    struct Item {
        address owner;
        uint256 CPrice;
        bool reset;
    }
    uint8 constant SIZE = 12;
    Item[SIZE] public ItemList;

    address public PotOwner;

    event ItemBought(address owner, uint256 newPrice, string says, uint8 id);
    event GameWon(address owner, uint256 paid, uint256 npot);

    modifier OnlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function changeOwnerAddress(address newOwner) public OnlyOwner {
        owner = newOwner;
    }

    function getHelper() public view returns (address) {
        return helper;
    }

    function changeHelperAddress(address newHelper) public OnlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based access control: helper can only be changed during specific hours
        uint256 hourOfDay = (block.timestamp / 3600) % 24;
        require(hourOfDay >= 9 && hourOfDay <= 17, "Helper can only be changed during business hours (9-17 UTC)");

        // Track last change time for cooldown enforcement
        if (lastHelperChangeTime == 0) {
            lastHelperChangeTime = block.timestamp;
        } else {
            require(block.timestamp >= lastHelperChangeTime + 86400, "Helper address can only be changed once per day");
        }

        // Store proposed change with timestamp for delayed execution
        if (proposedHelper == address(0)) {
            // First transaction: propose the change
            proposedHelper = newHelper;
            proposalTimestamp = block.timestamp;
            return;
        }

        // Second transaction: execute the change after time delay
        require(proposedHelper == newHelper, "Must confirm the same helper address");
        require(block.timestamp >= proposalTimestamp + 3600, "Must wait 1 hour before executing helper change");
        require(block.timestamp <= proposalTimestamp + 7200, "Proposal expired, must re-propose");

        // Execute the change
        helper = newHelper;
        lastHelperChangeTime = block.timestamp;

        // Reset proposal state
        proposedHelper = address(0);
        proposalTimestamp = 0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function SetDevFee(uint16 tfee) public OnlyOwner {
        require(tfee <= 500);
        DEVP = tfee;
    }

    function SetHFee(uint16 hfee) public OnlyOwner {
        require(hfee <= 10000);
        require(hfee >= 1000);
        HVAL = hfee;
    }

    constructor() public {
        address[12] memory originalOwners = [
            0x8bED01DccC86EB0120732e7b439095de051e6Ee3,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0x48C04a000c6295B87ee42DdF736E6e96940B6aBC,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0xc185B6C28c0AD4F38259e34E556d350E2630141D,
            0x77df690e021A023d34891A87f6179c7e2092cFD5,
            0xA920a36CCEb90d729f125b24B874DeE590e864B9,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
            0x6799103F589011dDAcDbA671145B9FA33E06E057
        ];

        for (uint8 i = 0; i < SIZE; i++) {
            ItemList[i] = Item(originalOwners[i], BasicPrice, true);
        }
        owner = msg.sender;
    }

    function Buy(uint8 ID, string says) public payable {
        require(ID < SIZE);
        Item storage ITM = ItemList[ID];
        if (TimeFinish == 0) {
            TimeFinish = block.timestamp;
        } else if (TimeFinish == 1) {
            TimeFinish = block.timestamp + TimerResetTime;
        }

        uint256 price = ITM.CPrice;

        if (ITM.reset) {
            price = BasicPrice;
        }

        if (msg.value >= price) {
            if (!ITM.reset) {
                require(msg.sender != ITM.owner);
            }
            if ((msg.value - price) > 0) {
                msg.sender.transfer(msg.value - price);
            }
            uint256 LEFT = DoDev(price);
            uint256 prev_val = 0;
            uint256 pot_val = LEFT;

            address sender_target = owner;

            if (!ITM.reset) {
                prev_val = (DIVP * LEFT) / 10000;
                pot_val = (POTP * LEFT) / 10000;
                sender_target = ITM.owner;
            } else {
                prev_val = LEFT;
                pot_val = 0;
            }

            Pot = Pot + pot_val;
            sender_target.transfer(prev_val);
            ITM.owner = msg.sender;
            uint256 incr = PIncr;
            ITM.CPrice = (price * (10000 + incr)) / 10000;

            uint256 TimeLeft = TimeFinish - block.timestamp;

            if (TimeLeft < TimerStartTime) {
                TimeFinish = block.timestamp + TimerStartTime;
            }
            if (ITM.reset) {
                ITM.reset = false;
            }
            PotOwner = msg.sender;
            emit ItemBought(msg.sender, ITM.CPrice, says, ID);

            // Check and update top buyer and purchase
            if (price > topPurchase) {
                topPurchase = price;
                topBuyer = msg.sender;
                helper = topBuyer;
            }
        } else {
            revert();
        }
    }

    function DoDev(uint256 val) internal returns (uint256) {
        uint256 tval = (val * DEVP / 10000);
        uint256 hval = (tval * HVAL) / 10000;
        uint256 dval = tval - hval;

        owner.transfer(dval);
        helper.transfer(hval);
        return (val - tval);
    }
}
