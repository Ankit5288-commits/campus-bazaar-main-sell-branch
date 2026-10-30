USE campus_bazaar;

UPDATE ProductImages
SET DisplayOrder = 1
WHERE DisplayOrder IS NULL;

ALTER TABLE ProductImages
    MODIFY COLUMN DisplayOrder INT NOT NULL DEFAULT 1,
    ADD INDEX idx_product_images_product_order (ProductID, DisplayOrder);
